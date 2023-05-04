# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import argparse
from typing import Any, Optional

import viper.common.out as out
from viper.common.exceptions import ArgumentErrorCallback
from viper.core.config import console_output


class ArgumentParser(argparse.ArgumentParser):
    def print_usage(self, file: Optional[str] = None):
        raise ArgumentErrorCallback(self.format_usage())

    def print_help(self, file: Optional[str] = None):
        raise ArgumentErrorCallback(self.format_help())

    def error(self, message: str):
        raise ArgumentErrorCallback(message, "error")

    def exit(self, status: Optional[int] = 0, message: Optional[str] = None):
        if message:
            raise ArgumentErrorCallback(message)


class Command:
    cmd = ""
    description = ""
    args = None
    output = []
    fs_path_completion = False

    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog=self.cmd, description=self.description
        )

    def log(self, log_type: str, data: Any):
        self.output.append({"type": log_type, "data": data})
        out.print_output([{"type": log_type, "data": data}], console_output["filename"])


class Module:
    cmd = ""
    description = ""
    command_line = []
    args = None
    authors = []
    output = []

    def __init__(self):
        self.parser = ArgumentParser(prog=self.cmd, description=self.description)

    def set_commandline(self, command: str):
        self.command_line = command

    def log(self, log_type: str, data: Any):
        self.output.append({"type": log_type, "data": data})
        out.print_output(
            [{"type": log_type, "data": log_msg}], console_output["filename"]
        )

    def usage(self):
        self.log("", self.parser.format_usage())

    def help(self):
        self.log("", self.parser.format_help())

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
                    ret.update(
                        {
                            item: get_argparse_parser_actions(
                                subparser_action.choices[item]
                            )
                        }
                    )

    except AttributeError:
        pass

    return ret
