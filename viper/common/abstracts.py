# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

from viper.common.colors import *

class Module(object):
    cmd = ''
    description = ''
    args = []
    authors = []

    def set_args(self, args):
        self.args = args

    def usage(self):
        raise NotImplementedError

    def help(self):
        raise NotImplementedError

    def run(self, *args):
        raise NotImplementedError
