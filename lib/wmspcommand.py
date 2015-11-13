from .commands import Commands


class WMSPCommand():

    def __init__(self):
        self.name = ""
        self.args = {}


class WMSPCommands(Commands):

    def __init__(self):
        super(WMSPCommands, self).__init__()
        self.default_port = '80'

    def parse(self):
        """Prints the WMSP command object."""
        try:
            cmd = self.get("xPlayStrm")
            if cmd is None:
                return
            for k in cmd.args:
                self.stream_info[k] = cmd.args[k]

            self.stream_info["url"] = 'mmsh://' + \
                self.stream_info["host"] + self.stream_info["path"]
            self.add_port()

        except Exception as e:
            self._logger.error("Error parsing WMSP properties: %s", e)
