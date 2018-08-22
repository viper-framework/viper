# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from collections import defaultdict

from viper.common.abstracts import Command
from viper.common.utils import convert_size
from viper.core.database import Database


class Stats(Command):
    """
    This command allows you to generate basic statistics for the stored files.
    """
    cmd = "stats"
    description = "Viper Collection Statistics"

    def __init__(self):
        super(Stats, self).__init__()

        self.parser.add_argument('-t', '--top', type=int, help='Top x Items')

    def run(self, *args):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        # Set all Counters Dict
        extension_dict = defaultdict(int)
        mime_dict = defaultdict(int)
        tags_dict = defaultdict(int)
        size_list = []

        # Find all
        items = Database().find('all')

        if len(items) < 1:
            self.log('info', "No items in database to generate stats")
            return

        # Sort in to stats
        for item in items:
            if isinstance(item.name, bytes):
                # NOTE: In case you there are names stored as bytes in the database
                name = item.name.decode()
            else:
                name = item.name
            if '.' in name:
                ext = name.split('.')
                extension_dict[ext[-1]] += 1
            mime_dict[item.mime] += 1
            size_list.append(item.size)
            for t in item.tag:
                if t.tag:
                    tags_dict[t.tag] += 1

        avg_size = sum(size_list) / len(size_list)
        # all_stats = {'Total': len(items), 'File Extension': extension_dict, 'Mime': mime_dict, 'Tags': tags_dict,
        #             'Avg Size': avg_size, 'Largest': max(size_list), 'Smallest': min(size_list)}

        # Counter for top x
        if args.top:
            counter = args.top
            prefix = 'Top {0} '.format(counter)
        else:
            counter = len(items)
            prefix = ''

        # Project Stats Last as i have it iterate them all

        # Print all the results

        self.log('info', "Projects")
        self.log('table', dict(header=['Name', 'Count'], rows=[['Main', len(items)], ['Next', '10']]))

        # For Current Project
        self.log('info', "Current Project")

        # Extension
        self.log('info', "{0}Extensions".format(prefix))
        header = ['Ext', 'Count']
        rows = []

        for k in sorted(extension_dict, key=extension_dict.get, reverse=True)[:counter]:
            rows.append([k, extension_dict[k]])
        self.log('table', dict(header=header, rows=rows))

        # Mimes
        self.log('info', "{0}Mime Types".format(prefix))
        header = ['Mime', 'Count']
        rows = []
        for k in sorted(mime_dict, key=mime_dict.get, reverse=True)[:counter]:
            rows.append([k, mime_dict[k]])
        self.log('table', dict(header=header, rows=rows))

        # Tags
        self.log('info', "{0}Tags".format(prefix))
        header = ['Tag', 'Count']
        rows = []
        for k in sorted(tags_dict, key=tags_dict.get, reverse=True)[:counter]:
            rows.append([k, tags_dict[k]])
        self.log('table', dict(header=header, rows=rows))

        # Size
        self.log('info', "Size Stats")
        self.log('item', "Largest  {0}".format(convert_size(max(size_list))))
        self.log('item', "Smallest  {0}".format(convert_size(min(size_list))))
        self.log('item', "Average  {0}".format(convert_size(avg_size)))
