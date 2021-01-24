# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from viper.common.abstracts import Command
from viper.core.database import Database, Malware
from viper.core.storage import get_sample_path
from viper.core.session import __sessions__


class Child(Command):
    """
    This command is used to view or edit the parent child relationship between files.
    """
    cmd = "child"
    description = "Add or remove a child file"

    def __init__(self):
        super(Child, self).__init__()

        self.parser.add_argument('-a', '--add', metavar='SHA256', help="Add child file by sha256")
        self.parser.add_argument('-d', '--delete', metavar='SHA256', help="Delete Child")
        self.parser.add_argument('-l', '--list', action='store_true', help="List all Children")

    def run(self, *args):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        # This command requires a session to be opened.
        if not __sessions__.is_set():
            self.log('error', "No open session. This command expects a file to be open.")
            self.parser.print_usage()
            return

        # If no arguments are specified, there's not much to do.
        if args.add is None and args.delete is None and not args.list:
            self.parser.print_usage()
            return

        db = Database()

        if not db.find(key='sha256', value=__sessions__.current.file.sha256):
            self.log('error', "The opened file is not stored in the database. "
                              "If you want to add it use the `store` command.")
            return

        if args.add:
            if not db.find(key='sha256', value=args.add):
                self.log('error', "the child file is not found in the database. ")
                return

            if db.add_relation(__sessions__.current.file.sha256, args.add):
                self.log('info', "child added to the currently opened file")
                self.log('info', "Refreshing session to update attributes...")
                __sessions__.new(__sessions__.current.file.path)

        if args.delete:
            db.delete_relation(__sessions__.current.file.sha256, args.delete)
            self.log('info', "child removed from the currently opened file")

            self.log('info', "Refreshing session to update attributes...")
            __sessions__.new(__sessions__.current.file.path)

        if args.list:
            # Do something with this list. probably a nice table of id, name, sha256.
            child_ids = db.get_children(__sessions__.current.file.sha256)
            if child_ids:
                children = [ Database().Session().query(Malware).get(child_id) for child_id in child_ids ]
                child_details = [ (child.id, child.sha256, child.name) for child in children ]
                self.log("table", dict(header=['ID', 'SHA256', 'NAME'], rows=child_details))
                