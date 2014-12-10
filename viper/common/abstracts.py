# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import argparse


class ArgumentParser(argparse.ArgumentParser):

    def error(self, message):
        raise Exception('error: {}\n'.format(message))


class Module(object):
    cmd = ''
    description = ''
    args = []
    authors = []
    output = []

    def __init__(self):
        self.parser = ArgumentParser(prog=self.cmd, description=self.description, add_help=False)
        self.parser.add_argument('-h', '--help', action='store_true', help='show this help message')

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
        self.parsed_args = None
        try:
            self.parsed_args = self.parser.parse_args(self.args)
            if self.parsed_args.help:
                self.help()
                self.parsed_args = None
        except Exception as e:
            self.usage()
            self.log('', e)
