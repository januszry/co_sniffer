#!/usr/bin/env python2.7

import logging
from commands import Commands
logger = logging.getLogger(__name__)


class HTTPCommand():

    def __init__(self):
        self.name = ""
        self.signature = 0
        self.args = {}


class HTTPCommands(Commands):

    def __init__(self):
        super(HTTPCommands, self).__init__()
        self.default_port = '80'

    def parse(self):
        """Get stream info from HTTPCommands object."""
        try:
            # get GET
            cmd = self.get('GET')
            if cmd is None:
                return
            for k in cmd.args:
                self.stream_info[k] = cmd.args[k]

            self.stream_info['url'] = 'http://' + \
                self.stream_info['host'] + self.stream_info['path']
            self.add_port()

        except Exception as e:
            logger.error("Error parsing HTTP properties: %s", e)
