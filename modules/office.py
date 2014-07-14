# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

'''
Code based on the python-oletools package by Philippe Lagadec 2012-10-18
http://www.decalage.info/python/oletools
'''

import os
import re
import string
import zlib
import struct
import getopt
import zipfile
import xml.etree.ElementTree as ET

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __sessions__

try:
    import OleFileIO_PL
    HAVE_OLE = True
except ImportError:
    HAVE_OLE = False

class Office(Module):
    cmd = 'office'
    description = 'Office OLE Parser'
    authors = ['Kevin Breen', 'nex']

    ##
    # HELPER FUNCTIONS
    #

    def detect_flash(self, data):
        matches = []
        for match in re.finditer('CWS|FWS', data):
            start = match.start()
            if (start + 8) > len(data):
                # Header size larger than remaining data,
                # this is not a SWF.
                continue

            # TODO: one struct.unpack should be simpler.
            # Read Header
            header = data[start:start+3]
            # Read Version
            ver = struct.unpack('<b', data[start+3])[0]
            # Error check for version above 20
            # TODO: is this accurate? (check SWF specifications).
            if ver > 20:
                continue

            # Read SWF Size.
            size = struct.unpack('<i', data[start+4:start+8])[0]
            if (start + size) > len(data) or size < 1024:
                # Declared size larger than remaining data, this is not
                # a SWF or declared size too small for a usual SWF.
                continue

            # Read SWF into buffer. If compressed read uncompressed size.
            swf = data[start:start+size]
            is_compressed = False
            swf_deflate = None
            if 'CWS' in header:
                is_compressed = True
                # Data after header (8 bytes) until the end is compressed
                # with zlib. Attempt to decompress it to check if it is valid.
                compressed_data = swf[8:]

                try:
                    swf_deflate = zlib.decompress(compressed_data)
                except:
                    continue

            # Else we don't check anything at this stage, we only assume it is a
            # valid SWF. So there might be false positives for uncompressed SWF.
            matches.append((start, size, is_compressed, swf, swf_deflate))

        return matches

    # Used to clean some of the section names returned in metatimes
    def string_clean(self, line):
        return filter(lambda x: x in string.printable, line)

    ##
    # OLE FUNCTIONS
    #

    def metadata(self, ole):
        meta = ole.get_metadata()
        for attribs in ['SUMMARY_ATTRIBS', 'DOCSUM_ATTRIBS']:
            print_info("{0} Metadata".format(attribs))
            rows = []
            for key in getattr(meta, attribs):
                rows.append([key, getattr(meta, key)])

            print(table(header=['Name', 'Value'], rows=rows))

        ole.close()

    def metatimes(self, ole):
        rows = []
        # Root document.
        rows.append(['Root', ole.root.getctime(), ole.root.getmtime()])

        # All other objects
        for obj in ole.listdir(streams=True, storages=True):
            rows.append([
                self.string_clean('/'.join(obj)),
                ole.getmtime(obj),
                ole.getctime(obj)
            ])

        print_info("OLE Structure:")
        print(table(header=['Object', 'Creation', 'Modified'], rows=rows))

        ole.close()

    def export(self, ole, export_path):
        if not os.path.exists(export_path):
            try:
                os.makedirs(export_path)
            except Exception as e:
                print_error("Unable to create directory at {0}: {1}".format(export_path, e))
                return
        else:
            if not os.path.isdir(export_path):
                print_error("You need to specify a folder, not a file")
                return

        for stream in ole.listdir(streams=True, storages=True):
            try:
                stream_content = ole.openstream(stream).read()
            except Exception as e:
                print_warning("Unable to open stream {0}: {1}".format(self.string_clean('/'.join(stream)), e))
                continue

            store_path = os.path.join(export_path, self.string_clean('-'.join(stream)))

            flash_objects = self.detect_flash(ole.openstream(stream).read())
            if len(flash_objects) > 0:
                print_info("Saving Flash objects...")
                count = 1

                for flash in flash_objects:
                    # If SWF Is compressed save the swf and the decompressed data seperatly.
                    if flash[2]:
                        save_path = '{0}-FLASH-Decompressed{1}'.format(store_path, count)
                        with open(save_path, 'wb') as flash_out:
                            flash_out.write(flash[4])

                        print_item("Saved Decompressed Flash File to {0}".format(save_path))

                    save_path = '{0}-FLASH-{1}'.format(store_path, count)
                    with open(save_path, 'wb') as flash_out:
                        flash_out.write(flash[3])

                    print_item("Saved Flash File to {0}".format(save_path))
                    count += 1

            with open(store_path, 'wb') as out:
                out.write(stream_content)

            print_info("Saved stream to {0}".format(store_path))

        ole.close()

    def oleid(self, ole):
        has_summary = False
        is_encrypted = False
        is_word = False
        is_excel = False
        is_ppt = False
        is_visio = False
        has_macros = False
        has_flash = 0

        # SummaryInfo.
        if ole.exists('\x05SummaryInformation'):
            suminfo = ole.getproperties('\x05SummaryInformation')
            has_summary = True
            # Encryption check.
            if 0x13 in suminfo:
                if suminfo[0x13] & 1:
                    is_encrypted = True

        # Word Check.
        if ole.exists('WordDocument'):
            is_word = True
            s = ole.openstream(['WordDocument'])
            s.read(10)
            temp16 = struct.unpack("H", s.read(2))[0]

            if (temp16 & 0x0100) >> 8:
                is_encrypted = True

        # Excel Check.
        if ole.exists('Workbook') or ole.exists('Book'):
            is_excel = True

        # Macro Check.
        if ole.exists('Macros'):
            has_macros = True

        for obj in ole.listdir(streams=True, storages=True):
            if 'VBA' in obj:
                has_macros = True

        # PPT Check.
        if ole.exists('PowerPoint Document'):
            is_ppt = True

        # Visio check.
        if ole.exists('VisioDocument'):
            is_visio = True

        # Flash Check.
        for stream in ole.listdir():
            has_flash += len(self.detect_flash(ole.openstream(stream).read()))

        # Put it all together.
        rows = [
            ['Summery Information', has_summary],
            ['Word', is_word],
            ['Excel', is_excel],
            ['PowerPoint', is_ppt],
            ['Visio', is_visio],
            ['Encrypted', is_encrypted],
            ['Macros', has_macros],
            ['Flash Objects', has_flash]
        ]

        # Print the results.
        print_info("OLE Info:")
        # TODO: There are some non ascii chars that need stripping.
        print(table(header=['Test', 'Result'], rows=rows))

        ole.close()

    ##
    # XML FUNCTIONS
    #

    def meta_data(self, xml_string):
        doc_meta = []
        xml_root = ET.fromstring(xml_string)
        for child in xml_root:
            doc_meta.append([child.tag.split('}')[1], child.text])
        return doc_meta

    def xmlmeta(self, zip_xml):
        media_list = []
        meta_list = []
        embedded_list = []
        vba_list = []
        for name in zip_xml.namelist():
            if name == 'docProps/app.xml':
                meta1 = self.meta_data(zip_xml.read(name))
            if name == 'docProps/core.xml':
                meta2 = self.meta_data(zip_xml.read(name))
            if name.startswith('word/media/'):
                media_list.append(name.split('/')[-1])
            # if name is vba, need to add multiple macros
            if name.startswith('word/embeddings'):
                embedded_list.append(name.split('/')[-1])
            if name == 'word/vbaProject.bin':
                vba_list.append(name.split('/')[-1])

        # Print the results.
        print_info("App MetaData:")
        print(table(header=['Field', 'Value'], rows=meta1))
        print_info("Core MetaData:")
        print(table(header=['Field', 'Value'], rows=meta2))
        if len(embedded_list) > 0:
            print_info("Embedded Objects")
            for item in embedded_list:
                print_item(item)
        if len(vba_list) > 0:
            print_info("Macro Objects")
            for item in vba_list:
                print_item(item)
        if len(media_list) > 0:
            print_info("Media Objects")
            for item in media_list:
                print_item(item)

    def xmlstruct(self, zip_xml):
        print_info("Document Structure")
        for name in zip_xml.namelist():
            print_item(name)

    def xml_export(self, zip_xml, export_path):
        if not os.path.exists(export_path):
            try:
                os.makedirs(export_path)
            except Exception as e:
                print_error("Unable to create directory at {0}: {1}".format(export_path, e))
                return
        else:
            if not os.path.isdir(export_path):
                print_error("You need to specify a folder, not a file")
                return
        try:
            zip_xml.extractall(export_path)
            print_info("Saved all objects to {0}".format(export_path))
        except Exception as e:
            print_error("Unable to export objects: {0}".format(e))
            return
        return

    # Main starts here
    def run(self):
        if not __sessions__.is_set():
            print_error("No session opened")
            return

        if not HAVE_OLE:
            print_error("Missing dependency, install OleFileIO (`pip install OleFileIO_PL`)")
            return

        def usage():
            print("usage: office [-hmsoe:]")

        def help():
            usage()
            print("")
            print("Options:")
            print("\t--help (-h)\tShow this help message")
            print("\t--meta (-m)\tGet The Metadata")
            print("\t--struct (-s)\tShow The OLE Structure")
            print("\t--oleid (-o)\tGet The OLE Information")
            print("\t--export (-e)\tExport OLE Objects (specify destination folder)")
            print("")


        # Tests to check for valid Office structures
        OLE_FILE = OleFileIO_PL.isOleFile(__sessions__.current.file.path)
        XML_FILE = zipfile.is_zipfile(__sessions__.current.file.path)
        if OLE_FILE:
            ole = OleFileIO_PL.OleFileIO(__sessions__.current.file.path)
        elif XML_FILE:
            zip_xml = zipfile.ZipFile(__sessions__.current.file.path, 'r')
        else:
            print_error("Not A Valid Office Document")
            return

        try:
            opts, argv = getopt.getopt(self.args[0:], 'hmsoe:', ['help', 'meta', 'struct', 'oleid', 'export:'])
        except getopt.GetoptError as e:
            print(e)
            return

        for opt, value in opts:
            if opt in ('-e', '--export'):
                if OLE_FILE:
                    self.export(ole, value)
                    return
                elif XML_FILE:
                    self.xml_export(zip_xml, value)
                    return
            if opt in ('-h', '--help'):
                help()
                return
            if opt in ('-m','--meta'):
                if OLE_FILE:
                    self.metadata(ole)
                    return
                elif XML_FILE:
                    self.xmlmeta(zip_xml)
                    return
            if opt in ('-s','--struct'):
                if OLE_FILE:
                    self.metatimes(ole)
                    return
                elif XML_FILE:
                    self.xmlstruct(zip_xml)
                    return
            if opt in ('-o','--oleid'):
                if OLE_FILE:
                    self.oleid(ole)
                    return
                else:
                    return

        usage()
