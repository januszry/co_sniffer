#!/usr/bin/env python2.7

import os
import logging
from Commands import Commands, DELIMITER
logger = logging.getLogger(__name__)


class MMSCommand():

    def __init__(self):
        self.name = ""
        self.signature = 0
        self.args = {}


class MMSCommands(Commands):

    def __init__(self):
        super(MMSCommands, self).__init__()
        self.default_port = '1755'

    def parse(self):
        ''' Get stream info from MMSCommands object '''
        try:
            # CMD Connect info
            cmd = self.get("connect_info")
            if cmd is None:
                return
            for k in cmd.args:
                self.stream_info[k] = cmd.args[k]

            # CMD Request server file
            cmd = self.get("request_server_file")
            if cmd is None:
                return
            self.stream_info["server_file"] = cmd.args["server_file"]

            self.stream_info["url"] = 'mms://' + self.stream_info[
                "host"] + '/' + self.stream_info["server_file"]
            self.add_port()

        except Exception as e:
            logger.error("Error parsing MMS properties: %s", e)
