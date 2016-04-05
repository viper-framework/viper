# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import argparse
import viper.common.out as out

class ArgumentErrorCallback(Exception):
    def __init__(self, message, level=''):
        self.message = message.strip() + '\n'
        self.level = level.strip()

    def __str__(self):
        return '{}: {}'.format(self.level, self.message)

    def get(self):
        return self.level, self.message

class ArgumentParser(argparse.ArgumentParser):
    def print_usage(self):
        raise ArgumentErrorCallback(self.format_usage())

    def print_help(self):
        raise ArgumentErrorCallback(self.format_help())

    def error(self, message):
        raise ArgumentErrorCallback(message, 'error')

    def exit(self, status, message=None):
        if message is not None:
            raise ArgumentErrorCallback(message)

class Module(object):
    cmd = ''
    description = ''
    command_line = []
    args = None
    authors = []
    output = []

    def __init__(self):
        self.parser = ArgumentParser(prog=self.cmd, description=self.description)

    def set_commandline(self, command):
        self.command_line = command

    def log(self, event_type, event_data):
        self.output.append(dict(
            type=event_type,
            data=event_data
        ))

        if event_type:
            if event_type == 'table':
                print(out.table(event_data['header'], event_data['rows']))
            else:
                getattr(out, 'print_{0}'.format(event_type))(event_data)
        else:
            print(event_data)

    def usage(self):
        self.log('', self.parser.format_usage())

    def help(self):
        self.log('', self.parser.format_help())

    def run(self):
        try:
            self.args = self.parser.parse_args(self.command_line)
        except ArgumentErrorCallback as e:
            self.log(*e.get())
