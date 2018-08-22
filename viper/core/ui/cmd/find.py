# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from viper.common.abstracts import Command
from viper.core.database import Database
from viper.core.session import __sessions__


class Find(Command):
    """
    This command is used to search for files in the database.
    """
    cmd = "find"
    description = "Find a file"

    def __init__(self):
        super(Find, self).__init__()

        group = self.parser.add_mutually_exclusive_group()
        group.add_argument('-t', '--tags', action='store_true', help="List available tags and quit")
        group.add_argument('type', nargs='?', choices=["all", "latest", "name", "type", "mime", "md5", "sha1", "sha256", "tag", "note", "any", "ssdeep"], help="Where to search.")
        self.parser.add_argument("value", nargs='?', help="String to search.")

    def run(self, *args):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        db = Database()

        # One of the most useful search terms is by tag. With the --tags
        # argument we first retrieve a list of existing tags and the count
        # of files associated with each of them.
        if args.tags:
            # Retrieve list of tags.
            tags = db.list_tags()

            if tags:
                rows = []
                # For each tag, retrieve the count of files associated with it.
                for tag in tags:
                    count = len(db.find('tag', tag.tag))
                    rows.append([tag.tag, count])

                # Generate the table with the results.
                header = ['Tag', '# Entries']
                rows.sort(key=lambda x: x[1], reverse=True)
                self.log('table', dict(header=header, rows=rows))
            else:
                self.log('warning', "No tags available")

            return

        # At this point, if there are no search terms specified, return.
        if args.type is None:
            self.parser.print_usage()
            return

        key = args.type
        if key != 'all' and key != 'latest':
            try:
                # The second argument is the search value.
                value = args.value
            except IndexError:
                self.log('error', "You need to include a search term.")
                return
        else:
            value = None

        # Search all the files matching the given parameters.
        items = db.find(key, value)
        if not items:
            return

        # Populate the list of search results.
        rows = []
        count = 1
        for item in items:
            tag = ', '.join([t.tag for t in item.tag if t.tag])
            row = [count, item.name, item.mime, item.md5, tag]
            if key == 'ssdeep':
                row.append(item.ssdeep)
            if key == 'latest':
                row.append(item.created_at)

            rows.append(row)
            count += 1

        # Update find results in current session.
        __sessions__.find = items

        # Generate a table with the results.
        header = ['#', 'Name', 'Mime', 'MD5', 'Tags']
        if key == 'latest':
            header.append('Created At')
        if key == 'ssdeep':
            header.append("Ssdeep")

        self.log("table", dict(header=header, rows=rows))
