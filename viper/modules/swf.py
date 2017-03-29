# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import zlib
import struct
import tempfile
from io import BytesIO, open

try:
    import pylzma
    HAVE_PYLZMA = True
except ImportError:
    HAVE_PYLZMA = False

from viper.common.out import cyan
from viper.common.abstracts import Module
from viper.common.utils import hexdump, get_md5
from viper.core.session import __sessions__
from viper.core.database import Database


class SWF(Module):
    cmd = 'swf'
    description = 'Parse, analyze and decompress Flash objects'
    authors = ['nex']

    def __init__(self):
        super(SWF, self).__init__()
        self.parser.add_argument('-d', '--dump', metavar='dump_path', help='Dump the SWF object to the destination folder (default is tmpdir)')

    def parse_swf(self):
        # Open an handle to the opened file so that we can more easily
        # walk through it.
        swf = BytesIO(__sessions__.current.file.data)
        # Extract the file header, so we can detect the compression.
        header = swf.read(3)
        # Extract the Flash version, not really important.
        version = struct.unpack('<b', swf.read(1))[0]
        # Extract the actual SWF size, this is important to properly dump
        # the binary data.
        size = struct.unpack('<i', swf.read(4))[0]

        try:
            # Start from the beginning.
            swf.seek(0)
            # Extract the right amount of data from the opened file.
            data = swf.read(size)
        except Exception as e:
            self.log('warning', "Unable to read SWF data: {0}".format(e))
            data = None

        return header, version, size, data

    def decompress(self, dump_dir):

        # Check if the file type is right.
        # TODO: this might be a bit hacky, need to verify whether malformed
        # Flash exploit would get a different file type.
        if 'Flash' not in __sessions__.current.file.type:
            self.log('error', "The opened file doesn't appear to be a valid SWF object")
            return

        # Retrieve key information from the opened SWF file.
        header, version, size, data = self.parse_swf()
        # Decompressed data.
        decompressed = None

        # Check if the file is already a decompressed Flash object.
        if header == b'FWS':
            self.log('info', "The opened file doesn't appear to be compressed")
            return
        # Check if the file is compressed with zlib.
        elif header == b'CWS':
            self.log('info', "The opened file appears to be compressed with Zlib")

            # Open an handle on the compressed data.
            compressed = BytesIO(data)
            # Skip the header.
            compressed.read(3)
            # Decompress and reconstruct the Flash object.
            decompressed = b'FWS' + compressed.read(5) + zlib.decompress(compressed.read())
        # Check if the file is compressed with lzma.
        elif header == b'ZWS':
            self.log('info', "The opened file appears to be compressed with Lzma")

            # We need an third party library to decompress this.
            if not HAVE_PYLZMA:
                self.log('error', "Missing dependency, please install pylzma (`pip install pylzma`)")
                return

            # Open and handle on the compressed data.
            compressed = BytesIO(data)
            # Skip the header.
            compressed.read(3)
            # Decompress with pylzma and reconstruct the Flash object.
            # # ZWS(LZMA)
            # # | 4 bytes       | 4 bytes    | 4 bytes       | 5 bytes    | n bytes    | 6 bytes         |
            # # | 'ZWS'+version | scriptLen  | compressedLen | LZMA props | LZMA data  | LZMA end marker |
            decompressed = b'FWS' + compressed.read(5)
            compressed.read(4)  # skip compressedLen
            decompressed += pylzma.decompress(compressed.read())

        # If we obtained some decompressed data, we print it and eventually
        # dump it to file.
        if decompressed:
            # Print the decompressed data
            # TODO: this prints too much, need to find a better wayto display
            # this. Paginate?
            self.log('', cyan(hexdump(decompressed)))

            if dump_dir:
                # Dump the decompressed SWF file to the specified directory
                # or to the default temporary one.
                dump_path = os.path.join(dump_dir, '{0}.swf'.format(get_md5(decompressed)))
                with open(dump_path, 'wb') as handle:
                    handle.write(decompressed)

                self.log('info', "Flash object dumped at {0}".format(dump_path))


                # Set the parent-child relation between CWS-FWS
                this_parent = __sessions__.current.file.sha256
                # Directly open a session on the dumped Flash object.
                __sessions__.new(dump_path)

                db = Database()
                # Make sure parents is in database
                if not db.find(key='sha256', value=this_parent):
                    self.log('error', "the parent file is not found in the database. ")
                else:
                    db.add_parent(__sessions__.current.file.sha256, this_parent)


    def run(self):

        super(SWF, self).run()
        if self.args is None:
            return

        if not __sessions__.is_set():
            self.log('error', "No open session")
            return

        arg_dump = self.args.dump
        if arg_dump is None:
            arg_dump = tempfile.gettempdir()
        self.decompress(arg_dump)
