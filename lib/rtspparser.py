from .utils import convert_bytes_to_str
from .rtspcommand import RTSPCommand


class RTSPParser(object):

    def __init__(self):
        pass

    def rtsp_parse_packet(self, packet):
        """Parses the RTSP packet."""
        method = convert_bytes_to_str(packet.read_bytes(4))
        if method != 'PLAY':
            return None
        data = convert_bytes_to_str(packet.get_bytes(packet.size))
        if not data:
            return
        data = data.split('\r\n')

        rtsp_command = RTSPCommand()
        rtsp_command.name = 'PLAY'
        rtsp_command.args['url'] = data[0][data[0].find(' ') + 1:
                                           data[0].rfind(' ')]
        if '://' not in rtsp_command.args['url']:
            return

        return rtsp_command
