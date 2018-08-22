# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from viper.common.abstracts import Command
from viper.core.database import Database
from viper.core.session import __sessions__


class Tags(Command):
    """
    This command is used to modify the tags of the opened file.
    """
    cmd = "tags"
    description = "Modify tags of the opened file"

    def __init__(self):
        super(Tags, self).__init__()

        self.parser.add_argument('-a', '--add', metavar='TAG', help="Add tags to the opened file (comma separated)")
        self.parser.add_argument('-d', '--delete', metavar='TAG', help="Delete a tag from the opened file")

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
        # However, it could make sense to also retrieve a list of existing
        # tags from this command, and not just from the "find" command alone.
        if args.add is None and args.delete is None:
            self.parser.print_usage()
            return

        # TODO: handle situation where addition or deletion of a tag fail.
        db = Database()

        if not db.find(key='sha256', value=__sessions__.current.file.sha256):
            self.log('error', "The opened file is not stored in the database. "
                     "If you want to add it use the `store` command.")
            return

        if args.add:
            # Add specified tags to the database's entry belonging to
            # the opened file.
            db.add_tags(__sessions__.current.file.sha256, args.add)
            self.log('info', "Tags added to the currently opened file")

            # We refresh the opened session to update the attributes.
            # Namely, the list of tags returned by the 'info' command
            # needs to be re-generated, or it wouldn't show the new tags
            # until the existing session is closed a new one is opened.
            self.log('info', "Refreshing session to update attributes...")
            __sessions__.new(__sessions__.current.file.path)

        if args.delete:
            # Delete the tag from the database.
            db.delete_tag(args.delete, __sessions__.current.file.sha256)
            # Refresh the session so that the attributes of the file are
            # updated.
            self.log('info', "Refreshing session to update attributes...")
            __sessions__.new(__sessions__.current.file.path)
