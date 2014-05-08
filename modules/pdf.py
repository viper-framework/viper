# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

'''
This is just a wrapper for Didier Stevens PDF Tools
http://blog.didierstevens.com/programs/pdf-tools/
'''


import os
import getopt
import json

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __session__

from pdftools.pdfid import *


class PDFID(Module):
    cmd = 'pdfid'
    description = 'Extract PDF Stream Information'
    authors = ['Kevin Breen']

    def run(self):
        if not __session__.is_set():
            print_error("No session opened")
            return
        # Run the parser - Returns an XML DOM Instance
        print_info('Parsing PDF')
        pdfdata = PDFiD(__session__.file.path, False, True)
        # This converts to string
        pdfstring = PDFiD2String(pdfdata, True)
        # this converts to JSON
        pdfJSON = PDFiD2JSON(pdfdata, True)
        # convert from string
        this = json.loads(pdfJSON)
        jsonString = this[0]
        # Get general info and format
        genRows = []
        genRows.append(['PDF Header', jsonString["pdfid"]["header"]])
        genRows.append(['Total Entropy', jsonString["pdfid"]["totalEntropy"]])
        genRows.append(['Entropy In Streams', jsonString["pdfid"]["streamEntropy"]])
        genRows.append(['Entropy Out Streams', jsonString["pdfid"]["nonStreamEntropy"]])
        genRows.append(['Count %% EOF', jsonString["pdfid"]["countEof"]])
        genRows.append(['Data After EOF', jsonString["pdfid"]["countChatAfterLastEof"]])
        
        # If there are date sections lets get them as well

        dates = jsonString["pdfid"]["dates"]["date"]
        for date in dates:
            genRows.append([date['name'],date['value']])

        # get streams and counts then format
        streamRows = []
        pdfStreams = jsonString["pdfid"]["keywords"]["keyword"]
        for stream in pdfStreams:
            streamRows.append([stream["name"], stream["count"]])
        
        # Print the tables
        print_info("General Info")
        print(table(header=['Desc','Value'], rows=genRows))

        print_info("Stream & Count")
        print(table(header=['Name','Count'], rows=streamRows))

