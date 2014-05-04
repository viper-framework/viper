# Copyright (C) 2013-2014 Claudio "nex" Guarnieri.
# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

'''
code based on the python-oletools package by Philippe Lagadec 2012-10-18
http://www.decalage.info/python/oletools
'''



import os
import re
import string
import zlib
import struct
import getopt

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __session__

try:
    import OleFileIO_PL
    HAVE_OLE = True
except ImportError:
    HAVE_OLE = False

class Office(Module):
    cmd = 'office'
    description = 'Office OLE Parser'

    def run(self):
        if not __session__.is_set():
            print_error("No session opened")
            return

        if not HAVE_OLE:
            print_error("Missing dependency, pip install OleFileIO_PL")
            return

        def usage():
            print("usage: office [-hmto]")

        def help():
            usage()
            print("")
            print("Options:")
            print("\t--help (-h)\tShow this help message")
            print("\t--meta (-m)\tGet The Metadata")
            print("\t--time (-t)\tGet The TimeStamp Data")
            print("\t--oleid (-o)\tGet The OLE Information")
            print("")


        # Helper Functions
        def detectFlash(data):
            found = []
            for match in re.finditer('CWS|FWS', data):
                start = match.start()
                if start+8 > len(data):
                    # header size larger than remaining data, this is not a SWF
                    continue
                #TODO: one struct.unpack should be simpler
                # Read Header
                header = data[start:start+3]
                # Read Version
                ver = struct.unpack('<b', data[start+3])[0]
                # Error check for version above 20
                #TODO: is this accurate? (check SWF specifications)
                if ver > 20:
                    continue
                # Read SWF Size
                size = struct.unpack('<i', data[start+4:start+8])[0]
                if start+size > len(data) or size < 1024:
                    # declared size larger than remaining data, this is not a SWF
                    # or declared size too small for a usual SWF
                    continue
                # Read SWF into buffer. If compressed read uncompressed size.
                swf = data[start:start+size]
                compressed = False
                if 'CWS' in header:
                    compressed = True
                    # compressed SWF: data after header (8 bytes) until the end is
                    # compressed with zlib. Attempt to decompress it to check if it is
                    # valid
                    compressed_data = swf[8:]
                    try:
                        zlib.decompress(compressed_data)
                    except:
                        continue
                # else we don't check anything at this stage, we only assume it is a
                # valid SWF. So there might be false positives for uncompressed SWF.
                found.append((start, size, compressed))
                #print 'Found SWF start=%x, length=%d' % (start, size)
            return found
        
        # Used to clean some of the section names returned in metatimes
        def stringClean(line):
            return filter(lambda x: x in string.printable, line)


                    
        # Main Functions
            
        def metadata():
            # Check for valid OLE
            if not OleFileIO_PL.isOleFile(__session__.file.path):
                print_error("Not a valid OLE File")
                return
            ole = OleFileIO_PL.OleFileIO(__session__.file.path)
            meta = ole.get_metadata()
            # Need to split and format the metadata before printing to screen
            print meta.dump()
            ole.close()
        
        def metatimes():
            # Check for valid OLE
            if not OleFileIO_PL.isOleFile(__session__.file.path):
                print_error("Not a valid OLE File")
                return
            ole = OleFileIO_PL.OleFileIO(__session__.file.path)
            # Root Document
            mtime = ole.root.getmtime()
            ctime = ole.root.getctime()
            rows = []
            rows.append(['Root', ctime, mtime])
            # All other objects
            for obj in ole.listdir(streams=True, storages=True):
                rows.append([stringClean('/'.join(obj)), ole.getmtime(obj), ole.getctime(obj)])
            print_info("Time Data:")
            print(table(header=['Object', 'Creation', 'Modified'], rows=rows))
            ole.close()
            
        def oleid():
            sumcheck = False
            enccheck = False
            wordcheck = False
            excelcheck = False
            pptcheck = False
            visiocheck = False
            macrocheck = False
            flashcount = 0
            
            # Check for valid OLE
            if not OleFileIO_PL.isOleFile(__session__.file.path):
                print_error("Not a valid OLE File")
                return
            ole = OleFileIO_PL.OleFileIO(__session__.file.path)
            
            # SummaryInfo
            if ole.exists("\x05SummaryInformation"):
                suminfo = ole.getproperties("\x05SummaryInformation")
                sumcheck = True
                # Encryption Check
                if 0x13 in suminfo:
                    if suminfo[0x13] & 1:
                        enccheck = True
            
            # Word Check
            if ole.exists('WordDocument'):
                wordcheck = True
                s = ole.openstream(["WordDocument"])
                s.read(10)
                temp16 = struct.unpack("H", s.read(2))[0]
                fEncrypted = (temp16 & 0x0100) >> 8
                if fEncrypted:
                    enccheck = True
            
            # Excel Check
            if ole.exists('Workbook') or ole.exists('Book'):
                excelcheck = True
            
            # Macro Check
            if ole.exists('Macros'):
                macrocheck = True
            
            # PPT Check
            if ole.exists('PowerPoint Document'):
                pptcheck = True
            
            # Visio check
            if ole.exists('VisioDocument'):
                visiocheck = True
            
            # Flash Check
            for stream in ole.listdir():
                data = ole.openstream(stream).read()
                found = detectFlash(data)
                # just add to the count of Flash objects:
                flashcount += len(found)
                
            # put it all together
            rows = []
            rows.append(['Summery Information', sumcheck])
            rows.append(['Word', wordcheck])
            rows.append(['Excel', excelcheck])
            rows.append(['PowerPoint', pptcheck])
            rows.append(['Visio', visiocheck])
            rows.append(['Encrypted', enccheck])
            rows.append(['Macros', macrocheck])
            rows.append(['Flash Objects', flashcount])
            # Print the results
            print_info("OLE Info:")
            #there are some non ascii chars that need stripping
            print(table(header=['Test', 'Result'], rows=rows))
            ole.close()
            
        
        # Run Functions
        try:
            opts, argv = getopt.getopt(self.args[0:], 'hmtox', ['help', 'meta', 'time', 'oleid', 'xor'])
        except getopt.GetoptError as e:
            print(e)
            return

        for opt, value in opts:
            if opt in ('-h', '--help'):
                help()
                return
            if opt in ('-m','--meta'):
                metadata()
                return
            if opt in ('-t','--time'):
                metatimes()
                return
            if opt in ('-o','--oleid'):
                oleid()
                return
        help()

