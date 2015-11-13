import traceback

from .commands import Commands, DELIMITER


class AMFCommand(object):

    def __init__(self):
        self.name = ''
        self.transaction_id = 0
        self.args = []

    def __str__(self):
        return repr(self.args)


class AMFCommands(Commands):

    def __init__(self):
        super(AMFCommands, self).__init__()
        self.stream_info['extra'] = ''
        self.default_port = '1935'

    def parse(self):
        """Prints the amf command object."""
        try:
            # CMD connect
            cmd = self.get('connect')
            if not cmd:
                return
            for arg in cmd.args:
                if isinstance(arg, dict):
                    for k in arg:
                        self.stream_info[k] = arg[k]
                else:
                    extra_type = 'Unknown:'
                    if isinstance(arg, str):
                        extra_type = 'String:'
                    elif isinstance(arg, bool):
                        extra_type = 'Boolean:'
                    elif isinstance(arg, int):
                        extra_type = 'Int:'
                    self.stream_info['extra'] += extra_type + str(arg) + ' '

            # CMD play
            cmd = self.get('play')
            if not cmd:
                return
            for arg in cmd.args:
                if isinstance(arg, str) and arg:
                    self.stream_info['playPath'] = arg
                    break

            if 'tcUrl' in self.stream_info and 'playPath' in self.stream_info:
                self.stream_info['url'] = '/'.join(
                    [self.stream_info['tcUrl'].rstrip('/'),
                        self.stream_info['playPath']])
                self.add_port()

        except Exception as e:
            self._logger.error("Error parsing RTMP properties: %s", e)
            traceback.print_exc()

    def output(self, mode='txt'):
        ''' Output found stream in specified mode '''

        if mode == 'm3u':
            result = self.output_m3u()
        elif mode == 'rtmpdump':
            result = self.output_rtmpdump()
        else:
            result = self.output_txt()
        print(DELIMITER)
        print(result)
        print(DELIMITER)
        return result

    def output_txt(self):
        ''' Get plain text of stream properties '''

        result = [self.stream_info['url']]
        for p in ['app', 'pageUrl', 'swfUrl', 'tcUrl', 'playPath', 'extra']:
            if p in self.stream_info and len(self.stream_info[p]) > 0:
                result.append("{}={}".format(p, self.stream_info[p]))

        return ' '.join(result)

    def output_m3u(self):
        ''' Get m3u text of stream properties '''

        result = []
        result.append('#EXTINF:0,1, Stream')

        paras = [self.stream_info['url']]
        for p in ['app', 'pageUrl', 'swfUrl', 'tcUrl', 'playPath']:
            if p in self.stream_info:
                paras.append("{}={}".format(p, self.stream_info[p]))
        if 'extra' in self.stream_info:
            paras.append("conn={}".format(self.stream_info['extra']))
        paras.append('live=1')

        result.append(' '.join(paras))

        result = '\n'.join(result)
        return result

    def output_rtmpdump(self):
        ''' Get rtmpdump text of stream properties '''

        result = []

        paras = ['rtmpdump', '-r', self.stream_info['url']]
        if self.stream_info.get('app', None):
            paras.extend(['-a', self.stream_info['app']])
        if self.stream_info.get('tcUrl', None):
            paras.extend(['-t', self.stream_info['tcUrl']])
        if self.stream_info.get('playPath', None):
            paras.extend(['-y', self.stream_info['playPath']])
        if self.stream_info.get('swfUrl', None):
            paras.extend(['-W', self.stream_info['swfUrl']])
        if self.stream_info.get('pageUrl', None):
            paras.extend(['-p', self.stream_info['pageUrl']])
        if self.stream_info.get('flashVer', None):
            paras.extend(['-f', self.stream_info['flashVer']])
        if self.stream_info.get('extra', None):
            paras.extend(['-C', self.stream_info['extra']])
        paras.extend(['--live', '-o', 'output.flv'])

        result.append(' '.join(paras))

        result = '\n'.join(result)

        return result
