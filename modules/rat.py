# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os
import re
import getopt
import importlib

import yara

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __session__

class RAT(Module):
    cmd = 'rat'
    description = 'Extract information from known RAT families'
    authors = ['Kevin Breen', 'nex']

    def list(self):
        print_info("List of available RAT modules:")

        for folder, folders, files in os.walk('modules/rats/'):
            for file_name in files:
                if not file_name.endswith('.py') or file_name.startswith('__init__'):
                    continue

                print_item(os.path.join(folder, file_name))

    def get_config(self, family):
        if not __session__.is_set():
            print_error("No session opened")
            return

        try:
            module = importlib.import_module('modules.rats.{0}'.format(family))
        except ImportError:
            print_error("There is no module for family {0}".format(bold(family)))
            return

        config = module.config(__session__.file.data)
        if not config:
            print_error("No Configuration Detected")
            return

        rows = []
        for key, value in config.items():
            rows.append([key, value])

        rows = sorted(rows, key=lambda entry: entry[0])

        print_info("Configuration:")
        print(table(header=['Key', 'Value'], rows=rows))

    def auto(self):
        if not __session__.is_set():
            print_error("No session opened")
            return

        rules = yara.compile('data/yara/rats.yara')
        for match in rules.match(__session__.file.path):
            if 'family' in match.meta:
                print_info("Automatically detected supported RAT {0}".format(match.rule))
                self.get_config(match.meta['family'])
                return

        print_info("No known RAT detected")

    def run(self):
        def usage():
            print("usage: xtreme [-hafl]")

        def help():
            usage()
            print("")
            print("Options:")
            print("\t--help (-h)\tShow this help message")
            print("\t--auto (-a)\tAutomatically detect RAT")
            print("\t--family (-f)\tSpecify which RAT family")
            print("\t--list (-l)\tList available RAT modules")
            print("")

        try:
            opts, argv = getopt.getopt(self.args[0:], 'haf:l', ['help', 'auto', 'family=', 'list'])
        except getopt.GetoptError as e:
            print(e)
            return

        for opt, value in opts:
            if opt in ('-h', '--help'):
                help()
                return
            elif opt in ('-a', '--auto'):
                self.auto()
                return
            elif opt in ('-f', '--family'):
                self.get_config(value)
                return
            elif opt in ('-l', '--list'):
                self.list()
                return

        usage()
