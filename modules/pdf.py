# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os
import getopt
import json

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __sessions__

from pdftools.pdfid import *

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

    def usage(self):
        print("usage: pdf <command>")

    def help(self):
        self.usage()
        print("")
        print("Options:")
        print("\thelp\t\tShow this help message")
        print("\tid\t\tShow general information on the PDF")
        print("")

    def run(self):
        if len(self.args) == 0:
            self.help()
            return

        if self.args[0] == 'help':
            self.help()
        elif self.args[0] == 'id':
            self.pdf_id()
