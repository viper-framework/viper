# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os
import zlib
import struct
import getopt
from StringIO import StringIO

try:
    import pylzma
    HAVE_PYLZMA = True
except ImportError:
    HAVE_PYLZMA = False

from viper.common.out import *
from viper.common.abstracts import Module
from viper.common.utils import hexdump
from viper.core.session import __sessions__

class SWF(Module):
    cmd = 'swf'
    description = 'Parse and analyze Flash objects'
    authors = ['nex']

    def parse_swf(self):
        swf = open(__sessions__.current.file.path, 'rb')
        header = swf.read(3)
        version = struct.unpack('<b', swf.read(1))[0]
        size = struct.unpack('<i', swf.read(4))[0]

        try:
            swf.seek(0)
            data = swf.read(size)
        except Exception as e:
            print_warning("Unable to read SWF data: {0}".format(e))
            data = None

        return header, version, size, data

    def decompress(self):
        if not __sessions__.is_set():
            print_error("No session opened")
            return

        if not 'Flash' in __sessions__.current.file.type:
            print_error("The opened file doesn't appear to be a valid SWF object")
            return

        header, version, size, data = self.parse_swf()

        decompressed = None

        if header == 'FWS':
            print_info("The opened file doesn't appear to be compressed")
            return
        elif header == 'CWS':
            print_info("The opened file appears to be compressed with Zlib")

            compressed = StringIO(data)
            compressed.read(3)
            decompressed = 'FWS' + compressed.read(5) + zlib.decompress(compressed.read())
        elif header == 'ZWS':
            print_info("The opened file appears to be compressed with Lzma")

            if not HAVE_PYLZMA:
                print_error("Missing dependency, please install pylzma (`pip install pylzma`)")
                return

            compressed = StringIO(data)
            compressed.read(3)
            decompressed = 'FWS' + compressed.read(5) + pylzma.decompress(compressed.read())

        if decompressed:
            print(cyan(hexdump(decompressed)))

    def usage(self):
        print("usage: swf <command>")

    def help(self):
        self.usage()
        print("")
        print("Options:")
        print("\thelp\t\tShow this help message")
        print("\tdecompress\tAttempt to decompress the Flash object")
        print("")

    def run(self):
        if len(self.args) == 0:
            self.help()
            return

        if self.args[0] == 'help':
            self.help()
        elif self.args[0] == 'decompress':
            self.decompress()
