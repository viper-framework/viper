# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os
import json
import getopt
import urllib
import urllib2

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __sessions__

VIRUSTOTAL_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
KEY = 'a0283a2c3d55728300d064874239b5346fb991317e8449fe43c902879d758088'

class VirusTotal(Module):
    cmd = 'virustotal'
    description = 'Lookup the file on VirusTotal'
    authors = ['nex']

    def run(self):
        def usage():
            print("usage: virustotal [-h] [-s]")

        def help():
            usage()
            print("")
            print("Options:")
            print("\t--help (-h)\tShow this help message")
            print("\t--submit (-s)\tSubmit file to VirusTotal (by default it only looks up the hash)")
            print("")

        arg_submit = False

        try:
            opts, argv = getopt.getopt(self.args[0:], 'hv', ['help', 'submit'])
        except getopt.GetoptError as e:
            print(e)
            return

        for opt, value in opts:
            if opt in ('-h', '--help'):
                help()
                return
            elif opt in ('-s', '--submit'):
                arg_submit = True

        if not __sessions__.is_set():
            print_error("No session opened")
            return

        data = urllib.urlencode({'resource' : __sessions__.current.file.md5, 'apikey' : KEY})

        try:
            request = urllib2.Request(VIRUSTOTAL_URL, data)
            response = urllib2.urlopen(request)
            response_data = response.read()
        except Exception as e:
            print_error("Failed: {0}".format(e))
            return

        try:
            virustotal = json.loads(response_data)
        except ValueError as e:
            print_error("Failed: {0}".format(e))

        rows = []
        if 'scans' in virustotal:
            for engine, signature in virustotal['scans'].items():
                if signature['detected']:
                    signature = signature['result']
                else:
                    signature = ''
                rows.append([engine, signature])

        if rows:
            print_info("VirusTotal Report:")
            print(table(['Antivirus', 'Signature'], rows))

            if arg_submit:
                print("")
                print_info("The file is already available on VirusTotal, no need to submit")
        else:
            print_info("The file does not appear to be on VirusTotal yet")
            # TODO: Add routine to upload files.
            pass
