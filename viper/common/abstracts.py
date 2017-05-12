# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import argparse
import viper.common.out as out
from viper.core.config import console_output
from viper.common.exceptions import ArgumentErrorCallback


class ArgumentParser(argparse.ArgumentParser):
    def print_usage(self, file=None):
        raise ArgumentErrorCallback(self.format_usage())

    def print_help(self, file=None):
        raise ArgumentErrorCallback(self.format_help())

    def error(self, message):
        raise ArgumentErrorCallback(message, 'error')

    def exit(self, status=0, message=None):
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
        out.print_output([{'type': event_type, 'data': event_data}], console_output['filename'])

    def usage(self):
        self.log('', self.parser.format_usage())

    def help(self):
        self.log('', self.parser.format_help())

    def run(self):
        try:
            self.args = self.parser.parse_args(self.command_line)
        except ArgumentErrorCallback as e:
            self.log(*e.get())


def get_argparse_parser_actions(parser):
    """introspect argparse object and return list of parameters/options/arguments"""
    ret = {}

    parser_actions = [(x.option_strings, x.choices, x.help) for x in parser._actions]
    for parser_action in parser_actions:
        if parser_action[1]:
            for action in parser_action[1]:
                ret.update({action: parser_action[2]})
        if isinstance(parser_action[0], list):
            for option in parser_action[0]:
                # ignore short options (only add --help and not -h)
                if option.startswith("--"):
                    ret.update({option: parser_action[2]})
        else:
            ret.update({parser_action[0]: parser_action[2]})

    return ret


def get_argparse_subparser_actions(parser):
    """introspect argparse subparser object"""
    ret = {}
    try:
        for subparser_action in parser._subparsers._actions:
            if isinstance(subparser_action, argparse._SubParsersAction):
                for item in list(subparser_action.choices):
                    ret.update({item: get_argparse_parser_actions(subparser_action.choices[item])})

    except AttributeError:
        pass

    return ret
