# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from viper.common.abstracts import Command
from viper.core.session import __sessions__


class Sessions(Command):
    """
    This command is used to list and switch across all the opened sessions.
    """
    cmd = "sessions"
    description = "List or switch sessions"

    def __init__(self):
        super(Sessions, self).__init__()

        group = self.parser.add_mutually_exclusive_group()
        group.add_argument('-l', '--list', action='store_true', help="List all existing sessions")
        group.add_argument('-s', '--switch', type=int, help="Switch to the specified session")

    def run(self, *args):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        if args.list:
            if not __sessions__.sessions:
                self.log('info', "There are no opened sessions")
                return

            rows = []
            for session in __sessions__.sessions:
                current = ''
                if session == __sessions__.current:
                    current = 'Yes'

                rows.append([
                    session.id,
                    session.file.name,
                    session.file.md5,
                    session.created_at,
                    current
                ])

            self.log('info', "Opened Sessions:")
            self.log("table", dict(header=['#', 'Name', 'MD5', 'Created At', 'Current'], rows=rows))
        elif args.switch:
            for session in __sessions__.sessions:
                if args.switch == session.id:
                    __sessions__.switch(session)
                    return

            self.log('warning', "The specified session ID doesn't seem to exist")
        else:
            self.parser.print_usage()
