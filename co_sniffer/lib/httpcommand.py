from .commands import Commands


class HTTPCommand(object):

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
            self._logger.error("Error parsing HTTP properties: %s", e)

    def output_txt(self):
        """Get plain text of stream properties."""
        result = [self.stream_info['url']]
        for k, v in self.stream_info.items():
            if k in ['user-agent', 'referer']:
                result.append("{}: {}".format(k, v))

        return '\n'.join(result)
