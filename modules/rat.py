# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os
import re
import getopt
import importlib

import yara

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __sessions__

class RAT(Module):
    cmd = 'rat'
    description = 'Extract information from known RAT families'
    authors = ['Kevin Breen', 'nex']

    def list(self):
        self.log('info', "List of available RAT modules:")

        for folder, folders, files in os.walk('modules/rats/'):
            for file_name in files:
                if not file_name.endswith('.py') or file_name.startswith('__init__'):
                    continue

                self.log('item', os.path.join(folder, file_name))

    def get_config(self, family):
        if not __sessions__.is_set():
            self.log('error', "No session opened")
            return

        try:
            module = importlib.import_module('modules.rats.{0}'.format(family))
        except ImportError:
            self.log('error', "There is no module for family {0}".format(bold(family)))
            return

        config = module.config(__sessions__.current.file.data)
        if not config:
            self.log('error', "No Configuration Detected")
            return

        rows = []
        for key, value in config.items():
            rows.append([key, value])

        rows = sorted(rows, key=lambda entry: entry[0])

        self.log('info', "Configuration:")
        self.log('table', dict(header=['Key', 'Value'], rows=rows))

    def auto(self):
        if not __sessions__.is_set():
            self.log('error', "No session opened")
            return

        rules = yara.compile('data/yara/rats.yara')
        for match in rules.match(__sessions__.current.file.path):
            if 'family' in match.meta:
                self.log('info', "Automatically detected supported RAT {0}".format(match.rule))
                self.get_config(match.meta['family'])
                return

        self.log('info', "No known RAT detected")

    def run(self):
        def usage():
            self.log('', "usage: rat [-hafl]")

        def help():
            usage()
            self.log('', "")
            self.log('', "Options:")
            self.log('', "\t--help (-h)\tShow this help message")
            self.log('', "\t--auto (-a)\tAutomatically detect RAT")
            self.log('', "\t--family (-f)\tSpecify which RAT family")
            self.log('', "\t--list (-l)\tList available RAT modules")
            self.log('', "")

        try:
            opts, argv = getopt.getopt(self.args[0:], 'haf:l', ['help', 'auto', 'family=', 'list'])
        except getopt.GetoptError as e:
            self.log('', e)
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
