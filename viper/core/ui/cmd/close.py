# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from typing import Any

from viper.common.abstracts import Command
from viper.core.sessions import sessions


class Close(Command):
    """
    This command resets the open session.
    After that, all handles to the open file should be closed and the
    shell should be restored to the default prompt.
    """

    cmd = "close"
    description = "Close the current session"

    def run(self, *args: Any):
        try:
            self.parser.parse_args(args)
        except SystemExit:
            return

        sessions.close()
