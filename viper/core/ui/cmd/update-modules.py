# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from viper.common.abstracts import Command
from viper.core.plugins import load_commands, __modules__


class UpdateModules(Command):
    """
    This command downloads modules from the GitHub repository at
    https://github.com/viper-framework/viper-modules
    """
    cmd = "update-modules"
    description = "Download Viper modules from the community GitHub repository"

    def run(self, *args):
        self.log("info", "Updating modules...")
