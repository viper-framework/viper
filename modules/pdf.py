# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os
import json
import getopt
import tempfile

from viper.common.out import *
from viper.common.abstracts import Module
from viper.common.utils import get_type
from viper.core.session import __sessions__

from pdftools.pdfid import *
from peepdf.PDFConsole import PDFConsole
from peepdf.PDFCore import PDFParser

class PDF(Module):
    cmd = 'pdf'
    description = 'Parse and analyze PDF documents'
    authors = ['Kevin Breen', 'nex']

    def pdf_id(self):
        if not __sessions__.is_set():
            self.log('error', 'No session opened')
            return

        if 'PDF' not in __sessions__.current.file.type:
            self.log('error', "The opened file doesn't appear to be a PDF document")
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
        
        self.log('info', "General Info:")
        self.log('table', dict(header=['Desc','Value'], rows=info))

        self.log('info', "Streams & Count:")
        self.log('table', dict(header=['Name','Count'], rows=streams))

    def streams(self):

        def usage():
            self.log('', "usage: pdf stream [-o=steam] [-d=folder]")

        def help():
            usage()
            self.log('', "")
            self.log('', "Options:")
            self.log('', "\t--help (-h)\tShow this help message")
            self.log('', "\t--dump (-d)\tDestination directory to store resource files in")
            self.log('', "\t--open (-o)\tOpen a session on the specified resource")
            self.log('', "")

        def get_streams():
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
            object_counter = 1

            for i in range(len(pdf.body)):
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

                        result = [
                            object_counter,
                            oid,
                            offset,
                            size,
                            get_type(decoded_stream)[:100]
                        ]

                        # If the stream needs to be dumped or opened, we do it
                        # and expand the results with the path to the stream dump.
                        if arg_open or arg_dump:
                            # If was instructed to dump, we already have a base folder.
                            if arg_dump:
                                folder = arg_dump
                            # Otherwise we juts generate a temporary one.
                            else:
                                folder = tempfile.gettempdir()
                            
                            # Confirm the dump path
                            if not os.path.exists(folder):
                                try:
                                    os.makedirs(folder)
                                except Exception as e:
                                    self.log('error', "Unable to create directory at {0}: {1}".format(folder, e))
                                    return results
                            else:
                                if not os.path.isdir(folder):
                                    self.log('error', "You need to specify a folder not a file")
                                    return results 
                            
                            # Dump stream to this path.
                            # TODO: sometimes there appear to be multiple streams
                            # with the same object ID. Is that even possible?
                            # It will cause conflicts.
                            dump_path = '{0}/{1}_{2}_pdf_stream.bin'.format(folder, __sessions__.current.file.md5, object_counter)

                            with open(dump_path, 'wb') as handle:
                                handle.write(decoded_stream.strip())

                            # Add dump path to the stream attributes.
                            result.append(dump_path)

                        # Update list of streams.
                        results.append(result)

                        object_counter += 1

                count += 1

            return results

        try:
            opts, argv = getopt.getopt(self.args[1:], 'ho:d:', ['help', 'open=', 'dump='])
        except getopt.GetoptError as e:
            self.log('', e)
            usage()
            return

        arg_open = None
        arg_dump = None

        for opt, value in opts:
            if opt in ('-h', '--help'):
                help()
                return
            elif opt in ('-o', '--open'):
                arg_open = value
            elif opt in ('-d', '--dump'):
                arg_dump = value

        if not __sessions__.is_set():
            self.log('error', "No session opened")
            return False

        if 'PDF' not in __sessions__.current.file.type:
            self.log('error', "The opened file doesn't appear to be a PDF document")
            return

        # Retrieve list of streams.
        streams = get_streams()

        # Show list of streams.
        header = ['#', 'ID', 'Offset', 'Size', 'Type']
        if arg_dump or arg_open:
            header.append('Dumped To')

        self.log('table', dict(header=header, rows=streams))

        # If the user requested to open a specific stream, we open a new
        # session on it.
        if arg_open:
            for stream in streams:
                if int(arg_open) == int(stream[0]):
                    __sessions__.new(stream[5])
                    return

    def usage(self):
        self.log('', "usage: pdf <command>")

    def help(self):
        self.usage()
        self.log('', "")
        self.log('', "Options:")
        self.log('', "\thelp\t\tShow this help message")
        self.log('', "\tid\t\tShow general information on the PDF")
        self.log('', "\tstreams\t\tExtract stream objects from PDF")
        self.log('', "")

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
