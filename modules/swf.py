# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os
import zlib
import struct
import getopt
import tempfile
from StringIO import StringIO

try:
    import pylzma
    HAVE_PYLZMA = True
except ImportError:
    HAVE_PYLZMA = False

from viper.common.out import *
from viper.common.abstracts import Module
from viper.common.utils import hexdump, get_md5
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
        def usage():
            print("usage: swf decompress [-d=folder]")

        def help():
            usage()
            print("")
            print("Options:")
            print("\t--help (-h)\tShow this help message")
            print("\t--dump (-d)\tDump the SWF object to the destination folder (default is /tmp)")
            print("")

        try:
            opts, argv = getopt.getopt(self.args[1:], 'hd', ['help', 'dump'])
        except getopt.GetoptError as e:
            print(e)
            usage()
            return

        arg_dump = None

        for opt, value in opts:
            if opt in ('-h', '--help'):
                help()
                return
            elif opt in ('-d', '--dump'):
                if value:
                    arg_dump = value
                else:
                    arg_dump = tempfile.gettempdir()

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

            if arg_dump:
                dump_path = os.path.join(arg_dump, '{0}.swf'.format(get_md5(decompressed)))
                with open(dump_path, 'wb') as handle:
                    handle.write(decompressed)

                print_info("Flash object dumped at {0}".format(dump_path))

                __sessions__.new(dump_path)

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
