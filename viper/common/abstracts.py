# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

class Module(object):
    cmd = ''
    description = ''
    args = []
    authors = []
    output = []

    def set_args(self, args):
        self.args = args

    def log(self, event_type, event_data):
        self.output.append(dict(
            type=event_type,
            data=event_data
        ))

    def usage(self):
        raise NotImplementedError

    def help(self):
        raise NotImplementedError

    def run(self, *args):
        raise NotImplementedError
