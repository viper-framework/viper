# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from typing import Any

from viper.common.abstracts import Command
from viper.core.sessions import sessions


class Sessions(Command):
    """
    This command is used to list and switch across all the open sessions.
    """

    cmd = "sessions"
    description = "List or switch sessions"

    def __init__(self):
        super(Sessions, self).__init__()

        group = self.parser.add_mutually_exclusive_group()
        group.add_argument(
            "-l", "--list", action="store_true", help="List all existing sessions"
        )
        group.add_argument(
            "-s", "--switch", type=int, help="Switch to the specified session"
        )

    def run(self, *args: Any):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        if args.list:
            if not sessions.list():
                self.log("info", "There are no open sessions")
                return

            rows = []
            for session in sessions.list():
                current = ""
                if session == sessions.current:
                    current = "Yes"

                rows.append(
                    [
                        str(session.id),
                        session.file.name,
                        session.file.sha1,
                        session.created_at,
                        current,
                    ]
                )

            self.log("info", "Opened Sessions:")
            self.log(
                "table",
                {
                    "columns": ["#", "Name", "SHA1", "Created At", "Current"],
                    "rows": rows,
                },
            )
        elif args.switch:
            for session in sessions.list():
                if args.switch == session.id:
                    sessions.switch(session)
                    return

            self.log("warning", "The specified session ID doesn't seem to exist")
        else:
            self.parser.print_usage()
