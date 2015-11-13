from .rtspcommand import RTSPCommand


class RTSPParser(object):

    def __init__(self):
        pass

    def rtsp_parse_packet(self, packet):
        """Parses the RTSP packet."""
        method = packet.read_bytes(4)
        if method != 'PLAY':
            return None
        data = packet.get_bytes(packet.size).split('\r\n')

        rtsp_command = RTSPCommand()
        rtsp_command.name = 'PLAY'
        rtsp_command.args['url'] = data[0][data[0].find(' ') + 1:
                                           data[0].rfind(' ')]
        if '://' not in rtsp_command.args['url']:
            return None

        return rtsp_command
