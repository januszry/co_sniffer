from .utils import convert_bytes_to_str
from .httpcommand import HTTPCommand


class HTTPParser(object):

    def __init__(self):
        pass

    def http_parse_packet(self, packet):
        """Parses the HTTP packet."""

        method = convert_bytes_to_str(packet.read_bytes(3))
        if not method or method.upper() not in ['GET', 'HTT', 'ICY']:
            return None
        data = convert_bytes_to_str(packet.get_bytes(packet.size))
        if not data:
            return
        data = data.split('\r\n\r\n')[0].split('\r\n')

        http_cmd = HTTPCommand()
        if method == 'GET':
            if len(data) < 2:  # At least GET and HOST are needed
                return None

            http_cmd.name = 'GET'
            http_cmd.args['path'] = data[0][
                data[0].find(' ') + 1: data[0].rfind(' ')]
            for c in data:
                if ': ' not in c:
                    continue
                (k, v) = c.split(': ', 1)
                v = v.strip()
                if k.lower() in ['host', 'user-agent', 'referer'] and v:
                    http_cmd.args[k.lower()] = v

            if not http_cmd.args.get('host'):
                return None
            return http_cmd

        # Check if reverse session indicates a valid stream media
        elif method == 'HTT' or method == 'ICY':
            http_content_types = [
                'audio',
                'video',
                'application/vnd.apple.mpegurl',
                'application/x-mpegurl',
                'application/flv',
                'application/ogg',
                'flv-application/octet-stream',
            ]
            http_cmd.name = 'STREAM_RESP'
            for c in data:
                c = c.lower()
                for t in http_content_types:
                    prefixes = [
                        'content-type: {}'.format(t),
                        'content-type:{}'.format(t),
                    ]
                    for p in prefixes:
                        if c.startswith(p):
                            return http_cmd
