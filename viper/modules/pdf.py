# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import json
import tempfile

from viper.common.abstracts import Module
from viper.core.session import __sessions__

from .pdftools.pdfid import PDFiD, PDFiD2JSON
from .pdftools import (cPDFParser, PDF_ELEMENT_COMMENT, PDF_ELEMENT_INDIRECT_OBJECT,
                       PDF_ELEMENT_XREF, PDF_ELEMENT_TRAILER, PDF_ELEMENT_STARTXREF,
                       PDF_ELEMENT_MALFORMED, FormatOutput)


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
        parser_streams.add_argument('-s', '--show', help='Show the content of the specified resource')

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
            # Initialize pdf parser.
            parser = cPDFParser(__sessions__.current.file.path)

            # Generate statistics.
            results = []
            objects = []
            oid = 0

            while True:
                pdf_object = parser.GetObject()
                if pdf_object is None:
                    break
                oid += 1
                objects.append(pdf_object)
                obj_type = pdf_object.type
                obj_id = '/'
                if obj_type == PDF_ELEMENT_STARTXREF:
                    obj_content = pdf_object.index
                    obj_type = 'STARTXREF'
                elif obj_type == PDF_ELEMENT_COMMENT:
                    obj_content = pdf_object.comment.encode()
                    obj_type = 'COMMENT'
                elif obj_type in (PDF_ELEMENT_MALFORMED, PDF_ELEMENT_TRAILER, PDF_ELEMENT_XREF,
                                  PDF_ELEMENT_INDIRECT_OBJECT):
                    obj_content = dump_content(pdf_object.content)
                    if obj_type == PDF_ELEMENT_MALFORMED:
                        obj_type = 'MALFORMED'
                    elif obj_type == PDF_ELEMENT_TRAILER:
                        obj_type = 'TRAILER'
                    elif obj_type == PDF_ELEMENT_XREF:
                        obj_type = 'XREF'
                    elif obj_type == PDF_ELEMENT_INDIRECT_OBJECT:
                        obj_id = pdf_object.id
                        obj_type = pdf_object.GetType()

                else:
                    # Can it happen?
                    continue

                if isinstance(obj_content, int):
                    obj_len = 0
                else:
                    obj_len = len(obj_content)
                result = [oid, obj_id, obj_len, obj_type]
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
                    if obj_len == 0:
                        continue
                    # Dump stream to this path.
                    dump_path = '{0}/{1}_{2}_pdf_stream.bin'.format(folder, __sessions__.current.file.md5, oid)
                    with open(dump_path, 'wb') as handle:
                        handle.write(obj_content)

                    # Add dump path to the stream attributes.
                    result.append(dump_path)
                elif arg_show and int(arg_show) == int(oid):
                    to_print = FormatOutput(obj_content, True)
                    if isinstance(to_print, int):
                        self.log('info', to_print)
                    else:
                        self.log('info', to_print.decode())
                    if pdf_object.type == PDF_ELEMENT_INDIRECT_OBJECT and pdf_object.ContainsStream():
                        self.log('Success', 'Stream content:')
                        self.log('info', FormatOutput(pdf_object.Stream(True), True).decode())

                # Update list of streams.
                results.append(result)
            return sorted(results, key=lambda x: int(x[0]))

        def dump_content(data):
            if isinstance(data, list):
                return b''.join([x[1].encode() for x in data])
            else:
                return data.encode()

        arg_open = self.args.open
        arg_dump = self.args.dump
        arg_show = self.args.show

        # Retrieve list of streams.
        streams = get_streams()

        if not arg_show:
            # Show list of streams.
            header = ['#', 'Object ID', 'Size', 'Type']
            if arg_dump or arg_open:
                header.append('Dumped To')

            self.log('table', dict(header=header, rows=streams))

        # If the user requested to open a specific stream, we open a new
        # session on it.
        if arg_open:
            for stream in streams:
                if int(arg_open) == int(stream[0]):
                    __sessions__.new(stream[4])
                    return

    def run(self):
        super(PDF, self).run()
        if self.args is None:
            return

        if not __sessions__.is_set():
            self.log('error', "No open session. This command expects a file to be open.")
            return False

        if 'PDF' not in __sessions__.current.file.type:
            # A file with '%PDF' signature inside first 1024 bytes is a valid
            # PDF file. magic lib doesn't detect it if there is an offset
            header = __sessions__.current.file.data[:1024]

            if b'%PDF' not in header:
                self.log('error', "The opened file doesn't appear to be a PDF document")
                return

        if self.args.subname == 'id':
            self.pdf_id()
        elif self.args.subname == 'streams':
            self.streams()
        else:
            self.log('error', 'At least one of the parameters is required')
            self.usage()
