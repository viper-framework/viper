# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
from typing import Any

from viper.common.abstracts import Command


class Clear(Command):
    """
    This command simply clears the shell.
    """

    cmd = "clear"
    description = "Clear the console"

    def run(self, *args: Any):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        os.system("clear")
