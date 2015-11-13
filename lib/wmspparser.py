from .utils import convert_bytes_to_str
from .wmspcommand import WMSPCommand


class WMSPParser(object):

    def __init__(self):
        pass

    def wmsp_parse_packet(self, packet, dport):
        """
        Parses the WMSP packet
        """
        method = convert_bytes_to_str(packet.read_bytes(3))
        if method != 'GET':
            return None
        data = convert_bytes_to_str(packet.get_bytes(packet.size))
        if not data:
            return
        data = data.split('\r\n')

        if len(data) < 2:
            return

        result = {}
        result['path'] = data[0][data[0].find(' ') + 1: data[0].rfind(' ')]

        for i in data:
            if ': ' in i:
                ti = i.find(': ')
                k = i[:ti]
                v = i[ti + 2:]
                if k == 'Pragma' and 'xPlayStrm' in v:
                    result['xPlayStrm'] = v[v.find('=') + 1:]
                if k == 'Host':
                    result['host'] = v

        wmsp_command = WMSPCommand()
        if 'xPlayStrm' in result and 'host' in result and 'path' in result:
            wmsp_command.name = 'xPlayStrm'
            wmsp_command.args['host'] = result['host'].split(
                ':')[0].rstrip('/') + ':' + str(dport)
            wmsp_command.args['path'] = result['path']
            return wmsp_command
        else:
            return
