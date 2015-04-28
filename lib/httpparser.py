#!/usr/bin/env python2.7

from httpcommand import HTTPCommand


class HTTPParser(object):

    def __init__(self):
        pass

    def http_parse_packet(self, packet):
        """Parses the HTTP packet."""

        method = packet.read_bytes(3).upper()
        if method != 'GET' and method != 'HTT' and method != 'ICY':
            return None
        data = packet.get_bytes(packet.size).split('\r\n\r\n')[0].split('\r\n')

        http_cmd = HTTPCommand()
        if method == 'GET':
            if len(data) < 2:  # At least GET and HOST are needed
                return None

            http_cmd.name = 'GET'
            http_cmd.args['path'] = data[0][
                data[0].find(' ') + 1: data[0].rfind(' ')]
            for c in data:
                if ': ' in c and 'host' in c.lower():
                    http_cmd.args['host'] = c[c.find(': ') + 2:]
                    if not http_cmd.args['host']:
                        return None
                    return http_cmd

        # Check if reverse session indicates a valid stream media
        elif method == 'HTT' or method == 'ICY':
            http_content_type_prefixes = [
                'content-type: audio',
                'content-type:audio',
                'content-type:video',
                'content-type: application/vnd.apple.mpegurl',
                'content-type:application/vnd.apple.mpegurl',
                'content-type: application/x-mpegurl',
                'content-type:application/x-mpegurl',
                'content-type: application/flv',
                'content-type:application/flv',
                'content-type: flv-application/octet-stream',
                'content-type:flv-application/octet-stream']
            http_cmd.name = 'STREAM_RESP'
            for c in data:
                c = c.lower()
                for p in http_content_type_prefixes:
                    if c.startswith(p):
                        return http_cmd
