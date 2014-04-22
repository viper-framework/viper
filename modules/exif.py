# Copyright (C) 2013-2014 Claudio "nex" Guarnieri.
# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os
import getopt

from viper.common.colors import bold
from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.database import Database
from viper.core.session import __session__

try:
    import exiftool
    HAVE_EXIF = True
except ImportError:
    HAVE_EXIF = False

class Exif(Module):
    cmd = 'exif'
    description = 'Extract Exif MetaData'

    def run(self):
        if not __session__.is_set():
            print_error("No session opened")
            return

        if not HAVE_EXIF:
            print_error("Missing dependency, install pyexiftool")
            return

        def usage():
            print("usage: exif [-h]")

        def help():
            usage()
            print("")
            print("Options:")
            print("\t--help (-h)\tShow this help message")
            print("")

        try:
            opts, argv = getopt.getopt(self.args[0:], 'h', ['help'])
        except getopt.GetoptError as e:
            print(e)
            return

        for opt, value in opts:
            if opt in ('-h', '--help'):
                help()
                return

        try:
            with exiftool.ExifTool() as et:
                metadata = et.get_metadata(__session__.file.path)
        except OSError:
            print_error("Exiftool is not installed")
            return

        rows = []
        for key, value in metadata.items():
            rows.append([key, value])

        rows = sorted(rows, key=lambda entry: entry[0])

        print_info("MetaData:")
        print(table(header=['Key', 'Value'], rows=rows))
