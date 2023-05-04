# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from typing import Any

from viper.common.abstracts import Command
from viper.core.database import Database
from viper.core.sessions import sessions


class Rename(Command):
    """
    This command renames the currently open file in the database.
    """

    cmd = "rename"
    description = "Rename the file in the database"

    def run(self, *args: Any):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        if sessions.is_set():
            if not sessions.current.file.id:
                self.log(
                    "error",
                    "The open file does not have an ID, have you stored it yet?",
                )
                return

            self.log(
                "info",
                f"Current name is: [bold]{sessions.current.file.name}[/bold]",
            )

            new_name = input("New name: ")
            if not new_name:
                self.log("error", "File name can't  be empty!")
                return

            Database().rename(sessions.current.file.id, new_name)

            self.log("info", "Refreshing session to update attributes...")
            sessions.new(sessions.current.file.path)
        else:
            self.log(
                "error", "No open session. This command expects a file to be open."
            )
