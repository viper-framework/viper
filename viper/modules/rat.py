# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import importlib

from viper.common.out import bold
from viper.common.abstracts import Module
from viper.core.session import __sessions__
from viper.common.constants import VIPER_ROOT

try:
    from scandir import walk
except ImportError:
    from os import walk

try:
    import yara
    HAVE_YARA = True
except ImportError:
    HAVE_YARA = False


class RAT(Module):
    cmd = 'rat'
    description = 'Extract information from known RAT families'
    authors = ['Kevin Breen', 'nex']

    def __init__(self):
        super(RAT, self).__init__()
        group = self.parser.add_mutually_exclusive_group(required=True)
        group.add_argument('-a', '--auto', action='store_true', help='Automatically detect RAT')
        group.add_argument('-f', '--family', help='Specify which RAT family')
        group.add_argument('-l', '--list', action='store_true', help='List available RAT modules')

    def list(self):
        self.log('info', "List of available RAT modules:")

        for folder, folders, files in walk(os.path.join(VIPER_ROOT, 'viper/modules/rats/')):
            for file_name in files:
                if not file_name.endswith('.py') or file_name.startswith('__init__'):
                    continue

                self.log('item', os.path.join(folder, file_name))

    def get_config(self, family):
        if not __sessions__.is_set():
            self.log('error', "No open session")
            return

        try:
            module = importlib.import_module('viper.modules.rats.{0}'.format(family))
        except ImportError:
            self.log('error', "There is no module for family {0}".format(bold(family)))
            return

        try:
            config = module.config(__sessions__.current.file.data)
        except Exception:
            config = None
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
        if not HAVE_YARA:
            self.log('error', "Missing dependency, install yara (see http://plusvic.github.io/yara/)")
            return

        if not __sessions__.is_set():
            self.log('error', "No open session")
            return

        rules_paths = [
            '/usr/share/viper/yara/rats.yara',
            os.path.join(VIPER_ROOT, 'data/yara/rats.yara')
        ]

        rules_path = None
        for cur_path in rules_paths:
            if os.path.exists(cur_path):
                rules_path = cur_path
                break

        rules = yara.compile(rules_path)
        for match in rules.match(__sessions__.current.file.path):
            if 'family' in match.meta:
                self.log('info', "Automatically detected supported RAT {0}".format(match.rule))
                self.get_config(match.meta['family'])
                return

        self.log('info', "No known RAT detected")

    def run(self):
        super(RAT, self).run()

        if self.args is None:
            return

        if self.args.auto:
            self.auto()
        elif self.args.family:
            self.get_config(self.args.family)
        elif self.args.list:
            self.list()
