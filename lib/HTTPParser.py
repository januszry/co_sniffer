#!/usr/bin/env python2.7

import traceback
import Utils
from HTTPCommand import HTTPCommand


class HTTPParser(object):
    def __init__(self):
        pass

    def http_parse_packet(self, packet):
        """
        Parses the HTTP packet
        """

        method = packet.read_bytes(3).upper()
        if method != 'GET' and method != 'HTT' and method != 'ICY':
            return None
        data = packet.get_bytes(packet.size).split('\r\n\r\n')[0].split('\r\n')

        http_cmd = HTTPCommand()
        if method == 'GET':
            if len(data) < 2:  # At least GET and HOST are needed
                return None

            http_cmd.name = 'GET'
            http_cmd.args['path'] = data[0][data[0].find(' ') + 1:
                                                        data[0].rfind(' ')]
            for c in data:
                if ': ' in c and 'host' in c.lower():
                    http_cmd.args['host'] = c[c.find(': ') + 2:]
                    if not http_cmd.args['host']:
                        return None
                    return http_cmd

        elif method == 'HTT' or method == 'ICY':  # Check if reverse session indicates a valid stream media
            http_cmd.name = 'STREAM_RESP'
            for c in data:
                c = c.lower()
                if c.startswith('content-type: audio') or \
                        c.startswith('content-type:audio') or \
                        c.startswith('content-type: video') or \
                        c.startswith('content-type:video') or \
                        c.startswith('content-type: application/vnd.apple.mpegurl') or \
                        c.startswith('content-type:application/vnd.apple.mpegurl') or \
                        c.startswith('content-type: application/x-mpegurl') or \
                        c.startswith('content-type:application/x-mpegurl') or \
                        c.startswith('content-type: application/flv') or \
                        c.startswith('content-type:application/flv') or \
                        c.startswith('content-type: flv-application/octet-stream') or \
                        c.startswith('content-type:flv-application/octet-stream') or \
                        c.startswith('server:streaming-transfer') or \
                        c.startswith('server: streaming-transfer'):
                    return http_cmd
