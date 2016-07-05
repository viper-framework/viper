# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import json
import tempfile

from viper.common.abstracts import Module
from viper.common.utils import get_type
from viper.core.session import __sessions__

from pdftools.pdfid import PDFiD, PDFiD2JSON
from peepdf.PDFCore import PDFParser


class PDF(Module):
    cmd = 'pdf'
    description = 'Parse and analyze PDF documents'
    authors = ['Kevin Breen', 'nex']

    def __init__(self):
        super(PDF, self).__init__()
        subparsers = self.parser.add_subparsers(dest='subname')
        subparsers.add_parser('id', help='Show general information on the PDF')

        parser_streams = subparsers.add_parser('streams', help='Extract stream objects from PDF')
        parser_streams.add_argument('-d', '--dump', help='Destination directory to store resource files in')
        parser_streams.add_argument('-o', '--open', help='Open a session on the specified resource')

    def pdf_id(self):

        # Run the parser - Returns an XML DOM Instance.
        pdf_data = PDFiD(__sessions__.current.file.path, False, True)

        # This converts to string.
        # pdf_string = PDFiD2String(pdf_data, True)

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
            info.append([date['name'], date['value']])

        # Get streams, counts and format.
        streams = []
        for stream in pdf['pdfid']['keywords']['keyword']:
            streams.append([stream['name'], stream['count']])

        self.log('info', "General Info:")
        self.log('table', dict(header=['Desc', 'Value'], rows=info))

        self.log('info', "Streams & Count:")
        self.log('table', dict(header=['Name', 'Count'], rows=streams))

    def streams(self):

        def get_streams():
            # This function is brutally ripped from Brandon Dixon's swf_mastah.py.

            # Initialize peepdf parser.
            parser = PDFParser()
            # Parse currently opened PDF document.
            ret, pdf = parser.parse(__sessions__.current.file.path, True, False)
            # Generate statistics.

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

        arg_open = self.args.open
        arg_dump = self.args.dump

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

    def run(self):
        super(PDF, self).run()
        if self.args is None:
            return

        if not __sessions__.is_set():
            self.log('error', "No open session")
            return False

        if 'PDF' not in __sessions__.current.file.type:
            # A file with '%PDF' signature inside first 1024 bytes is a valid
            # PDF file. magic lib doesn't detect it if there is an offset
            header = open(__sessions__.current.file.path, 'rb').read(1024)
            if '%PDF' not in header:
                self.log('error', "The opened file doesn't appear to be a PDF document")
                return

        if self.args.subname == 'id':
            self.pdf_id()
        elif self.args.subname == 'streams':
            self.streams()
        else:
            self.log('error', 'At least one of the parameters is required')
            self.usage()
