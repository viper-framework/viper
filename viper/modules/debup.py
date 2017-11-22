# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os

from viper.common.abstracts import Module
from viper.core.session import __sessions__

try:
    import olefile

    HAVE_OLE = True
except ImportError:
    HAVE_OLE = False


class Debup(Module):
    cmd = 'debup'
    description = 'Parse McAfee BUP Files'
    authors = ['Kevin Breen', 'nex']

    def __init__(self):
        super(Debup, self).__init__()
        self.parser.add_argument('-s', '--session', action='store_true', default=False,
                                 help='Switch session to the quarantined file')

    def xordata(self, data, key):
        encoded = bytearray(data)
        for i in range(len(encoded)):
            encoded[i] ^= key
        return encoded

    def run(self):

        super(Debup, self).run()
        if self.args is None:
            return

        if not __sessions__.is_set():
            self.log('error', "No open session")
            return

        if not HAVE_OLE:
            self.log('error', "Missing dependency, install olefile (`pip install olefile`)")
            return

        # Check for valid OLE
        if not olefile.isOleFile(__sessions__.current.file.path):
            self.log('error', "Not a valid BUP File")
            return

        # Extract all the contents from the bup file.

        ole = olefile.OleFileIO(__sessions__.current.file.path)
        # We know that BUPs are xor'd with 6A which is dec 106 for the decoder

        # This is the stored file.
        data = self.xordata(ole.openstream('File_0').read(), 106)

        # Get the details page
        data2 = self.xordata(ole.openstream('Details').read(), 106)

        # Close the OLE
        ole.close()

        # Process the details file
        rows = []

        if isinstance(data2, bytes):
            data2 = data2.decode()
        lines = data2.decode().split('\n')

        filename = ''
        for line in lines:
            if line.startswith('OriginalName'):
                fullpath = line.split('=')[1]
                pathsplit = fullpath.split('\\')
                filename = str(pathsplit[-1][:-1])
            try:
                k, v = line.split('=')
                rows.append([k, v[:-1]])  # Strip the \r from v
            except Exception:
                pass

                # If we opted to switch session then do that
        if data and self.args.session:
            try:
                tempName = os.path.join('/tmp', filename)
                with open(tempName, 'wb') as temp:
                    temp.write(data)
                self.log('info', "Switching Session to Embedded File")
                __sessions__.new(tempName)
                return
            except Exception:
                self.log('error', "Unable to Switch Session")
        # Else just print the data
        else:
            self.log('info', "BUP Details:")
            self.log('table', dict(header=['Description', 'Value'], rows=rows))
