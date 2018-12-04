from .commands import Commands


class RTSPCommand():

    def __init__(self):
        self.name = ""
        self.args = {}


class RTSPCommands(Commands):

    def __init__(self):
        super(RTSPCommands, self).__init__()
        self.default_port = '554'

    def parse(self):
        """Get stream info from RTSPCommands object."""
        try:
            cmd = self.get("PLAY")
            if cmd is None:
                return
            for k in cmd.args:
                self.stream_info[k] = cmd.args[k]
            self.add_port()

        except Exception as e:
            self._logger.error("Error parsing RTSP properties: %s", e)
