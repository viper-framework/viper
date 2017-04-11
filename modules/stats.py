# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import math
from collections import defaultdict

from viper.common.abstracts import Module
from viper.core.database import Database
from viper.core.project import __project__

class Stats(Module):
    cmd = 'stats'
    description = 'Viper Statistics'
    authors = ['Kevin Breen']

    def __init__(self):
        super(Stats, self).__init__()
        self.parser.add_argument('-t', '--top', type=int, help='Top x Items')
        # Open connection to the database.
        self.db = Database()

    # http://stackoverflow.com/questions/5194057/better-way-to-convert-file-sizes-in-python
    def convert_size(self, size):
       size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
       i = int(math.floor(math.log(size,1024)))
       p = math.pow(1024,i)
       s = round(size/p,2)
       if (s > 0):
           return '%s %s' % (s,size_name[i])
       else:
           return '0B'

    def run(self):
        super(Stats, self).run()
        if self.args is None:
            return

        arg_top = self.args.top


        # Set all Counters Dict
        extension_dict = defaultdict(int)
        mime_dict = defaultdict(int)
        tags_dict = defaultdict(int)
        size_list = []
        
        # Find all
        items = self.db.find('all')
        # Sort in to stats
        for item in items:
            if '.' in item.name:
                ext = item.name.split('.')
                extension_dict[ext[-1]] += 1
            mime_dict[item.mime] += 1
            size_list.append(item.size)
            for t in item.tag:
                if t.tag:
                    tags_dict[t.tag] += 1
        
        avg_size = sum(size_list) / len(size_list)
        all_stats = {'Total':len(items), 'File Extension':extension_dict, 'Mime':mime_dict, 'Tags':tags_dict, 'Avg Size':avg_size, 'Largest':max(size_list), 'Smallest':min(size_list)}

        # Counter for top x
        if arg_top:
            counter = arg_top
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
        self.log('item', "Largest  {0}".format(self.convert_size(max(size_list))))
        self.log('item', "Smallest  {0}".format(self.convert_size(min(size_list))))
        self.log('item', "Average  {0}".format(self.convert_size(avg_size)))