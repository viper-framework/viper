# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os
import getopt

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __session__

try:
    import OleFileIO_PL
    HAVE_OLE = True
except ImportError:
    HAVE_OLE = False

class Debup(Module):
    cmd = 'debup'
    description = 'Parse McAfee BUP Files'
    authors = ['nex']

    def run(self):
        if not __session__.is_set():
            print_error("No session opened")
            return

        if not HAVE_OLE:
            print_error("Missing dependency, install OleFileIO (`pip install OleFileIO_PL`)")
            return
        
        def xordata(data, key):
            encoded = bytearray(data)
            for i in range(len(encoded)):
                encoded[i] ^= key
            return encoded

        def bupdetails():
            # Check for valid OLE
            if not OleFileIO_PL.isOleFile(__session__.file.path):
                print_error("Not a valid BUP File")
                return
            ole = OleFileIO_PL.OleFileIO(__session__.file.path)
            # We know that BUPS are xor'd with 6A which is dec 106 for the decoder
            details = xordata(ole.openstream('Details').read(), 106)
            # the rest of this is just formating
            lines = details.split('\n')
            rows = []
            for line in lines:
                try:
                    k,v = line.split('=')
                    rows.append([k,v[:-1]]) #Strip the \r from v
                except:
                    pass
            print_info("BUP Details:")
            print(table(header=['Description', 'Value'], rows=rows))
            ole.close()

        def bupextract():
            # Check for valid OLE
            if not OleFileIO_PL.isOleFile(__session__.file.path):
                print_error("Not a valid BUP File")
                return
            ole = OleFileIO_PL.OleFileIO(__session__.file.path)
            # We know that BUPS are xor'd with 6A which is dec 106 for the decoder
            print_info("Switching Session to Embedded File")
            data = xordata(ole.openstream('File_0').read(), 106)
            # this is a lot of work jsut to get a filename.
            data2 = xordata(ole.openstream('Details').read(), 106)
            ole.close()
            lines = data2.split('\n')
            for line in lines:
                if line.startswith('OriginalName'):
                    fullpath = line.split('=')[1]
                    pathsplit = fullpath.split('\\')
                    filename = str(pathsplit[-1][:-1])
            # now lets write the data out to a file and get a session on it
            if data:
                tempName = os.path.join('/tmp', filename)
                with open(tempName, 'w') as temp:
                    temp.write(data)
                __session__.set(tempName)
                return
            else:
                print_error("Unble to Switch Session")

        # Run Functions
        try:
            opts, argv = getopt.getopt(self.args[0:], 'hs', ['help', 'session'])
        except getopt.GetoptError as e:
            print(e)
            return

        for opt, value in opts:
            if opt in ('-h', '--help'):
                help()
                return
            if opt in ('-s','--session'):
                bupextract()
                return
        bupdetails()


