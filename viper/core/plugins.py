# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import sys
import pkgutil
import inspect
import importlib
from os.path import expanduser

from viper.common.abstracts import Command, Module
from viper.common.abstracts import get_argparse_parser_actions
from viper.common.abstracts import get_argparse_subparser_actions
from viper.common.out import print_warning


def load_commands():
    # Import modules package.
    import viper.core.ui.cmd as cmd

    plugins = dict()

    # Walk recursively through all cmd and packages.
    for loader, cmd_name, ispkg in pkgutil.walk_packages(cmd.__path__, cmd.__name__ + '.'):
        # If current item is a package, skip.
        if ispkg:
            continue

        # Try to import the command, otherwise skip.
        try:
            cmd_module = importlib.import_module(cmd_name)
        except ImportError as e:
            print_warning("Something wrong happened while importing the command {0}: {1}".format(cmd_name, e))
            continue

        # Walk through all members of currently imported cmd.
        for member_name, member_object in inspect.getmembers(cmd_module):
            # Check if current member is a class.
            if inspect.isclass(member_object):
                # Yield the class if it's a subclass of Command.
                if issubclass(member_object, Command) and member_object is not Command:
                    instance = member_object()
                    plugins[member_object.cmd] = dict(obj=instance.run,
                                                      description=instance.description,
                                                      parser_args=get_argparse_parser_actions(instance.parser),
                                                      fs_path_completion=instance.fs_path_completion)

    return plugins


def load_modules():
    # Add $HOME/.viper/ as a Python path.
    sys.path.insert(0, os.path.join(expanduser("~"), ".viper"))

    try:
        import modules
    except ImportError:
        return dict()
    else:
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
                                                          categories=getattr(member_object, "categories", []),
                                                          parser_args=get_argparse_parser_actions(member_object().parser),
                                                          subparser_args=get_argparse_subparser_actions(member_object().parser))

        return plugins

__modules__ = load_modules()
