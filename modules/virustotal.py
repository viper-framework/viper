# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os
import json
import getopt

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __sessions__

VIRUSTOTAL_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
VIRUSTOTAL_URL_SUBMIT = 'https://www.virustotal.com/vtapi/v2/file/scan'
KEY = 'a0283a2c3d55728300d064874239b5346fb991317e8449fe43c902879d758088'

class VirusTotal(Module):
    cmd = 'virustotal'
    description = 'Lookup the file on VirusTotal'
    authors = ['nex']

    def run(self):
        def usage():
            self.log('', "usage: virustotal [-h] [-s]")

        def help():
            usage()
            self.log('', "")
            self.log('', "Options:")
            self.log('', "\t--help (-h)\tShow this help message")
            self.log('', "\t--submit (-s)\tSubmit file to VirusTotal (by default it only looks up the hash)")
            self.log('', "")

        arg_submit = False

        try:
            opts, argv = getopt.getopt(self.args[0:], 'hs', ['help', 'submit'])
        except getopt.GetoptError as e:
            self.log('', e)
            return

        for opt, value in opts:
            if opt in ('-h', '--help'):
                help()
                return
            elif opt in ('-s', '--submit'):
                arg_submit = True

        if not HAVE_REQUESTS:
            self.log('error', "Missing dependency, install requests (`pip install requests`)")
            return

        if not __sessions__.is_set():
            self.log('error', "No session opened")
            return

        data = {'resource' : __sessions__.current.file.md5, 'apikey' : KEY}

        try:
            response = requests.post(VIRUSTOTAL_URL, data=data)
        except Exception as e:
            self.log('error', "Failed performing request: {0}".format(e))
            return

        try:
            virustotal = response.json()
            # since python 2.7 the above line causes the Error dict object not callable
        except Exception as e:
            # workaround in case of python 2.7
            if str(e) == "'dict' object is not callable":
                try:
                    virustotal = response.json
                except Exception as e:
                    self.log('error', "Failed parsing the response: {0}".format(e))
                    self.log('error', "Data:\n{}".format(response.content))
                    return                        
            else:
                self.log('error', "Failed parsing the response: {0}".format(e))
                self.log('error', "Data:\n{}".format(response.content))
                return

        rows = []
        if 'scans' in virustotal:
            for engine, signature in virustotal['scans'].items():
                if signature['detected']:
                    signature = signature['result']
                else:
                    signature = ''
                rows.append([engine, signature])

        rows.sort()
        if rows:
            self.log('info', "VirusTotal Report:")
            self.log('table', dict(header=['Antivirus', 'Signature'], rows=rows))

            if arg_submit:
                self.log('', "")
                self.log('info', "The file is already available on VirusTotal, no need to submit")
        else:
            self.log('info', "The file does not appear to be on VirusTotal yet")

            if arg_submit:
                try:
                    data = {'apikey' : KEY}
                    files = {'file' : open(__sessions__.current.file.path, 'rb').read()}
                    response = requests.post(VIRUSTOTAL_URL_SUBMIT, data=data, files=files)
                except Exception as e:
                    self.log('error', "Failed Submit: {0}".format(e))
                    return

                try:
                    virustotal = response.json()
                    # since python 2.7 the above line causes the Error dict object not callable
                except Exception as e:
                    # workaround in case of python 2.7
                    if str(e) == "'dict' object is not callable":
                        try:
                            virustotal = response.json
                        except Exception as e:
                            self.log('error', "Failed parsing the response: {0}".format(e))
                            self.log('error', "Data:\n{}".format(response.content))
                            return                        
                    else:
                        self.log('error', "Failed parsing the response: {0}".format(e))
                        self.log('error', "Data:\n{}".format(response.content))
                        return

                if 'verbose_msg' in virustotal:
                    self.log('info', "{}: {}".format(bold("VirusTotal message"), virustotal['verbose_msg']))
