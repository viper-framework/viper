# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.


class Module(object):
    cmd = ''
    description = ''
    args = []
    authors = []
    output = []
    parser = None

    def set_args(self, args):
        self.args = args

    def log(self, event_type, event_data):
        self.output.append(dict(
            type=event_type,
            data=event_data
        ))

    def usage(self):
        self.log('', self.parser.format_usage())

    def help(self):
        self.log('', self.parser.format_help())

    def run(self, *args):
        raise NotImplementedError
