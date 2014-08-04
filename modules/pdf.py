# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os
import getopt
import json

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __sessions__

from pdftools.pdfid import *
from peepdf.PDFConsole import PDFConsole
from peepdf.PDFCore import PDFParser

class PDF(Module):
    cmd = 'pdf'
    description = 'Extract PDF Stream Information'
    authors = ['Kevin Breen', 'nex']

    def pdf_id(self):
        if not __sessions__.is_set():
            print_error('No session opened')
            return

        # Run the parser - Returns an XML DOM Instance.
        pdf_data = PDFiD(__sessions__.current.file.path, False, True)

        # This converts to string.
        #pdf_string = PDFiD2String(pdf_data, True)

        # This converts to JSON.
        pdf_json = PDFiD2JSON(pdf_data, True)

        # Convert from string.
        pdf = json.loads(pdf_json)[0]

        # Get general info and format.
        info = [
            ['PDF Header', pdf['pdfid']['header']],
            ['Total Entropy', pdf['pdfid']['totalEntropy']],
            ['Entropy In Streams', pdf['pdfid']['streamEntropy']],
            ['Entropy Out Streams', pdf['pdfid']['nonStreamEntropy']],
            ['Count %% EOF', pdf['pdfid']['countEof']],
            ['Data After EOF', pdf['pdfid']['countChatAfterLastEof']]
        ]
        
        # If there are date sections lets get them as well.
        dates = pdf['pdfid']['dates']['date']
        for date in dates:
            info.append([date['name'],date['value']])

        # Get streams, counts and format.
        streams = []
        for stream in pdf['pdfid']['keywords']['keyword']:
            streams.append([stream['name'], stream['count']])
        
        print_info("General Info:")
        print(table(header=['Desc','Value'], rows=info))

        print_info("Streams & Count:")
        print(table(header=['Name','Count'], rows=streams))

    def streams(self):
        def get_type(data):
            try:
                import magic
            except ImportError:
                pass

            try:
                ms = magic.open(magic.MAGIC_NONE)
                ms.load()
                file_type = ms.buffer(data)
            except:
                try:
                    file_type = magic.from_buffer(data)
                except:
                    return ''
            finally:
                try:
                    ms.close()
                except:
                    pass

            return file_type

        def get_streams(oid=None):
            # This function is brutally ripped from Brandon Dixon's swf_mastah.py.

            # Initialize peepdf parser.
            parser = PDFParser()
            # Parse currently opened PDF document.
            ret, pdf = parser.parse(__sessions__.current.file.path, True, False)
            # Generate statistics.
            stats = pdf.getStats()

            results = []
            objects = []
            count = 0

            for version in range(len(stats['Version'])):
                body = pdf.body[count]
                objects = body.objects

                for index in objects:
                    oid = objects[index].id
                    offset = objects[index].offset
                    size = objects[index].size
                    details = objects[index].object

                    if details.type == 'stream':
                        encoded_stream = details.encodedStream
                        decoded_stream = details.decodedStream

                        #with open('/tmp/{0}_decoded.bin'.format(oid), 'wb') as handle:
                        #    handle.write(decoded_stream.strip())

                        results.append([
                            oid,
                            offset,
                            size,
                            get_type(decoded_stream)[:100]
                        ])

                count += 1

            return results

        streams = get_streams()

        print_info("List of streams:")
        print(table(header=['ID', 'Offset', 'Size', 'Type'], rows=streams))

    def usage(self):
        print("usage: pdf <command>")

    def help(self):
        self.usage()
        print("")
        print("Options:")
        print("\thelp\t\tShow this help message")
        print("\tid\t\tShow general information on the PDF")
        print("\tstreams\t\tExtract stream objects from PDF")
        print("")

    def run(self):
        if len(self.args) == 0:
            self.help()
            return

        if self.args[0] == 'help':
            self.help()
        elif self.args[0] == 'id':
            self.pdf_id()
        elif self.args[0] == 'streams':
            self.streams()
