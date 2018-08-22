# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from viper.core.plugins import load_commands
from viper.core.database import Database


class Commands(object):
    output = []

    def __init__(self):
        Database().__init__()
        # Map commands to their related functions.
        self.commands = load_commands()
