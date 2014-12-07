# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os
import getopt
import hashlib
import zipfile

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __sessions__

class Jar(Module):
    cmd = 'jar'
    description = 'Parse Java JAR archives'
    authors = ['Kevin Breen']
            
    def run(self):
        def usage():
            self.log('', "usage: jar [-hd]")

        def help():
            usage()
            self.log('', "")
            self.log('', "Options:")
            self.log('', "\t--help (-h)\tShow this help message")
            self.log('', "\t--dump (-d)\tExtract all items from jar")
            return

        def read_manifest(manifest):
            rows = []
            lines = manifest.split('\r\n')
            for line in lines:
                if len(line) > 1:
                    item, value = line.split(':')
                    rows.append([item, value])

            self.log('info', "Manifest File:")
            self.log('table', dict(header=['Item','Value'], rows=rows))

        try:
            opts, argv = getopt.getopt(self.args, 'hd:', ['help', 'dump='])
        except getopt.GetoptError as e:
            self.log('', e)
            return

        arg_dump = None
        for opt, value in opts:
            if opt in ('-d', '--dump'):
                arg_dump = value
            elif opt in ('-h', '--help'):
                help()
                return

        if not __sessions__.is_set():
            self.log('error', "No session opened")
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
                return
