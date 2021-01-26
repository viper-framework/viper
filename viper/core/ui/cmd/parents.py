# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from viper.common.abstracts import Command
from viper.core.database import Database, Malware
from viper.core.storage import get_sample_path
from viper.core.session import __sessions__


class Parents(Command):
    """
    This command is used to view or edit the parent child relationship between files.
    """
    cmd = "parents"
    description = "Add or remove a parent file"

    def __init__(self):
        super(Parents, self).__init__()

        group = self.parser.add_mutually_exclusive_group()
        group.add_argument('-a', '--add', metavar='SHA256', help="Add parent file by sha256")
        group.add_argument('-d', '--delete', metavar='SHA256', help="Delete Parent")
        group.add_argument('-l', '--list', action='store_true', help="List all parents")

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
                self.log('error', "the parent file is not found in the database. ")
                return

            if db.add_relation(args.add, __sessions__.current.file.sha256):
                self.log('info', "parent added to the currently opened file")
                self.log('info', "Refreshing session to update attributes...")
                __sessions__.new(__sessions__.current.file.path)

        if args.delete:
            db.delete_relation(args.delete, __sessions__.current.file.sha256)
            self.log('info', "parent removed from the currently opened file")

            self.log('info', "Refreshing session to update attributes...")
            __sessions__.new(__sessions__.current.file.path)

        if args.list:
            # Do something with this list. probably a nice table of id, name, sha256.
            parent_ids = db.get_parents(__sessions__.current.file.sha256)
            if parent_ids:
                parents = [ Database().Session().query(Malware).get(parent_id) for parent_id in parent_ids ]
                parent_details = [ (parent.id, parent.sha256, parent.name) for parent in parents ]
                self.log("table", dict(header=['ID', 'SHA256', 'NAME'], rows=parent_details))
            else:
                self.log('info', "No parents found.")
                