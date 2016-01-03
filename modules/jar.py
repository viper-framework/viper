# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import hashlib
import zipfile

from viper.common.abstracts import Module
from viper.core.session import __sessions__


class Jar(Module):
    cmd = 'jar'
    description = 'Parse Java JAR archives'
    authors = ['Kevin Breen']

    def __init__(self):
        super(Jar, self).__init__()
        self.parser.add_argument('-d ', '--dump', metavar='dump_path', help='Extract all items from jar')

    def run(self):

        def read_manifest(manifest):
            rows = []
            lines = manifest.split('\r\n')
            for line in lines:
                if len(line) > 1:
                    item, value = line.split(':')
                    rows.append([item, value])

            self.log('info', "Manifest File:")
            self.log('table', dict(header=['Item', 'Value'], rows=rows))

        super(Jar, self).run()
        if self.args is None:
            return

        arg_dump = self.args.dump

        if not __sessions__.is_set():
            self.log('error', "No open session")
            return

        if not zipfile.is_zipfile(__sessions__.current.file.path):
            self.log('error', "Doesn't Appear to be a valid jar archive")
            return

        with zipfile.ZipFile(__sessions__.current.file.path, 'r') as archive:
            jar_tree = []

            for name in archive.namelist():
                item_data = archive.read(name)

                if name == 'META-INF/MANIFEST.MF':
                    read_manifest(item_data)

                item_md5 = hashlib.md5(item_data).hexdigest()
                jar_tree.append([name, item_md5])

            self.log('info', "Jar Tree:")
            self.log('table', dict(header=['Java File', 'MD5'], rows=jar_tree))

            if arg_dump:
                archive.extractall(arg_dump)
                self.log('info', "Archive content extracted to {0}".format(arg_dump))
