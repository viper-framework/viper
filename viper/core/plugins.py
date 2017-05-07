# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import pkgutil
import inspect
import importlib
from argparse import _SubParsersAction

from viper.common.out import print_warning
from viper.common.abstracts import Module


def get_argparse_parser_actions(parser):
    """introspect argparse object and return list of parameters/options/arguments"""
    ret = {}

    parser_actions = [(x.option_strings, x.help) for x in parser._actions]
    for parser_action in parser_actions:
        if isinstance(parser_action[0], list):
            for option in parser_action[0]:
                # ignore short options (only add --help and not -h)
                if option.startswith("--"):
                    ret.update({option: parser_action[1]})
        else:
            ret.update({parser_action[0]: parser_action[1]})

    return ret


def get_argparse_subparser_actions(parser):
    """introspect argparse subparser object"""
    ret = {}
    try:
        for subparser_action in parser._subparsers._actions:
            if isinstance(subparser_action, _SubParsersAction):
                for item in list(subparser_action.choices):
                    ret.update({item: get_argparse_parser_actions(subparser_action.choices[item])})

    except AttributeError:
        pass

    return ret


def load_modules():
    # Import modules package.
    import viper.modules as modules

    plugins = dict()

    # Walk recursively through all modules and packages.
    for loader, module_name, ispkg in pkgutil.walk_packages(modules.__path__, modules.__name__ + '.'):
        # If current item is a package, skip.
        if ispkg:
            continue
        # Try to import the module, otherwise skip.
        try:
            module = importlib.import_module(module_name)
        except ImportError as e:
            print_warning("Something wrong happened while importing the module {0}: {1}".format(module_name, e))
            continue

        # Walk through all members of currently imported modules.
        for member_name, member_object in inspect.getmembers(module):
            # Check if current member is a class.
            if inspect.isclass(member_object):
                # Yield the class if it's a subclass of Module.
                if issubclass(member_object, Module) and member_object is not Module:
                    plugins[member_object.cmd] = dict(obj=member_object,
                                                      description=member_object.description,
                                                      parser_args=get_argparse_parser_actions(member_object().parser),
                                                      subparser_args=get_argparse_subparser_actions(member_object().parser))

    return plugins


__modules__ = load_modules()
