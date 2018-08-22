# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os

from viper.common.abstracts import Command


class Clear(Command):
    """
    This command simply clears the shell.
    """
    cmd = "clear"
    description = "Clear the console"

    def run(self, *args):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        os.system('clear')
