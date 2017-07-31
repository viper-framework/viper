# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import sys
import argparse
from distutils.spawn import find_executable
import pkg_resources

import logging

import viper.common.out as out
from viper.core.config import console_output
from viper.common.exceptions import ArgumentErrorCallback

log = logging.getLogger('viper')


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

    min_python_version = (2, 7)
    dependency_list_python = []
    dependency_list_system = []

    def __init__(self):
        self.parser = ArgumentParser(prog=self.cmd, description=self.description)

    def check(self):
        min_python_version = self._check_min_python_version()
        dep_python = self._check_dependencies_python()
        dep_system = self._check_dependencies_system()
        if min_python_version and dep_python and dep_system:
            return True
        else:
            return False

    def _check_min_python_version(self):
        if sys.version_info >= self.min_python_version:
            log.debug("{}: Python Version ok".format(self.__class__.__name__))
            return True
        else:
            log.warning("{}: Python Version NOT ok".format(self.__class__.__name__))
            return False

    def _check_dependencies_python(self):
        if not self.dependency_list_python:
            return True

        missing = []

        for item in self.dependency_list_python:
            try:
                pkg_resources.require(item)
            except pkg_resources.DistributionNotFound as err:
                log.debug("{}: Missing Python dependency: {}".format(self.__class__.__name__, err))
                missing.append(item)
            except pkg_resources.VersionConflict as err:
                log.debug("{}: Python dependency wrong version: {}".format(self.__class__.__name__, err))
                missing.append(item)

        if missing:
            log.warning("{}: Missing/Failed Python dependencies: {}".format(self.__class__.__name__, missing))
            return False

        return True

    def _check_dependencies_system(self):
        if not self.dependency_list_system:
            return True

        missing = [item for item in self.dependency_list_system if not find_executable(item)]

        if missing:
            log.warning("{}: Missing System dependencies: {}".format(self.__class__.__name__, missing))
            return False
        else:
            return True

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
