# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from viper.common.abstracts import Command
from viper.common.colors import bold
from viper.core.database import Database
from viper.core.session import __sessions__


class Rename(Command):
    """
    This command renames the currently opened file in the database.
    """
    cmd = "rename"
    description = "Rename the file in the database"

    def run(self, *args):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        if __sessions__.is_set():
            if not __sessions__.current.file.id:
                self.log('error', "The opened file does not have an ID, have you stored it yet?")
                return

            self.log('info', "Current name is: {}".format(bold(__sessions__.current.file.name)))

            new_name = input("New name: ")
            if not new_name:
                self.log('error', "File name can't  be empty!")
                return

            Database().rename(__sessions__.current.file.id, new_name)

            self.log('info', "Refreshing session to update attributes...")
            __sessions__.new(__sessions__.current.file.path)
        else:
            self.log('error', "No open session. This command expects a file to be open.")
