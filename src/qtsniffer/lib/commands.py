import logging

try:
    import urllib.parse as urlparse
except ImportError:
    import urlparse

DELIMITER = "*" * 80


class Commands(object):

    def __init__(self):
        self.commands = []
        self.stream_info = {}
        self.default_port = None
        self._logger = logging.getLogger(__name__)

    def __str__(self):
        result = 'Commands:\n' + DELIMITER + '\n'
        for i in self.commands:
            result += i.name + ': ' + str(i) + '\n'
        result += 'Stream Info:\n' + DELIMITER + '\n' + str(self.stream_info)
        return result

    def add(self, cmd):
        """Adds a new Command object."""
        e = self.get(cmd.name)
        if e:
            self.commands.remove(e)
        self.commands.append(cmd)

    def get(self, name):
        """Get an Command object by name."""
        for c in self.commands:
            if c.name == name:
                return c
        return None

    def count(self):
        """Returns the number of commands."""
        return len(self.commands)

    def parse(self):
        """Abstract method."""
        pass

    def add_port(self):
        """Add default port to self.stream_info["url"]."""
        parsed_url = urlparse.urlparse(self.stream_info['url'])
        if not self.default_port:
            return
        if parsed_url.port is None:
            port = self.default_port
        else:
            port = parsed_url.port
        self.stream_info['url'] = "{}://{}:{}{}".format(
            parsed_url.scheme,
            parsed_url.hostname,
            port,
            parsed_url.path)
        if parsed_url.query:
            self.stream_info['url'] += '?' + parsed_url.query

    def output(self, mode='txt'):
        self.parse()
        if mode == 'txt':
            result = self.output_txt()
            print(DELIMITER)
            print(result)
            print(DELIMITER)
            return result

    def output_txt(self):
        """Get plain text of stream properties."""
        result = [self.stream_info['url']]
        for k, v in self.stream_info.items():
            if k in ['user-agent', 'referer']:
                result.append("{}: {}".format(k, v))

        return '\n'.join(result)
