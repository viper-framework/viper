# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os
import getopt
import hashlib
import zipfile

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __sessions__

class javaparse(Module):
    cmd = 'jar'
    description = 'Read / Extract Jar Files'
    authors = ['Kevin Breen']
            
    def run(self):
        def usage():
            print("usage: jar [-hd]")

        def help():
            usage()
            print("")
            print("Options:")
            print("\t--help (-h)\tShow this help message")
            print("\t--dump (-d)\tExtract all items from jar")
            return

        def read_manifest(manifest):
            rows = []
            lines = manifest.split('\r\n')
            for line in lines:
                if len(line) > 1:
                    item, value = line.split(':')
                    rows.append([item, value])
            print_info("Manifest File")
            print(table(header=['Item','Value'], rows=rows))

        if not __sessions__.is_set():
            print_error("No session opened")
            return

        try:
            opts, argv = getopt.getopt(self.args, 'hd:', ['help', 'dump='])
        except getopt.GetoptError as e:
            print(e)
            return

        java_data = __sessions__.current.file.path
        arg_dump = None
        for opt, value in opts:
            if opt in ('-d', '--dump'):
                arg_dump = value
            elif opt in ('-h', '--help'):
                help()
                return
        jar_tree = []
        if zipfile.is_zipfile(java_data):
            with zipfile.ZipFile(java_data, 'r') as zip:
                for name in zip.namelist():
                    item_data = zip.read(name)
                    if arg_dump:
                        zip.extractall(arg_dump)
                        print_info("Items extracted to {0}".format(arg_dump))
                        return
                    if name == 'META-INF/MANIFEST.MF':
                        read_manifest(item_data)
                    item_md5 = hashlib.md5(item_data).hexdigest()
                    jar_tree.append([name, item_md5])
            print_info("Jar Tree")
            print(table(header=['Java File','MD5'], rows=jar_tree))
            return
        else:
            print_error("Doesn't Appear to be a valid jar archive")
            return
        help()
