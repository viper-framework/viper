from viper.common.colors import *

class Module(object):
    cmd = ''
    description = ''
    args = []

    def set_args(self, args):
        self.args = args

    def usage(self):
        raise NotImplementedError

    def help(self):
        raise NotImplementedError

    def run(self, *args):
        raise NotImplementedError
