# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os
import json
import time
import getopt

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __sessions__
from viper.core.database import Database
from viper.core.storage import get_sample_path

VIRUSTOTAL_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
VIRUSTOTAL_URL_SUBMIT = 'https://www.virustotal.com/vtapi/v2/file/scan'
VIRUSTOTAL_URL_RESUMBIT = 'https://www.virustotal.com/vtapi/v2/file/rescan'
KEY = 'a0283a2c3d55728300d064874239b5346fb991317e8449fe43c902879d758088'
TIMER = 25 # Public API key have 4 request per minute

class VirusTotal(Module):
    cmd = 'virustotal'
    description = 'Lookup the file on VirusTotal'
    authors = ['nex', 'dukebarman']

    def __init__(self):
        self.arg_scan = False
        self.arg_submit = False
        self.arg_resubmit = False

    def run(self):
        def usage():
            print("usage: virustotal [-h] [-s] [-r] [-n] [-e=avengine]")

        def report():
            data = {'resource' : __sessions__.current.file.md5, 'apikey' : KEY}

            try:
                response = requests.post(VIRUSTOTAL_URL, data=data)
            except Exception as e:
                print_error("Failed performing request: {0}".format(e))
                return

            try:
                virustotal = response.json()
            except Exception as e:
                print_error("Failed parsing the response: {0}".format(e))
                print_error("Data:\n{}".format(response.content))
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
                print_info("VirusTotal Report:")
                print(table(['Antivirus', 'Signature'], rows))
            else:
                print_info("The file does not appear to be on VirusTotal yet")

        def resubmit(file_md5):
            try:
                data = {'resource' : file_md5, 'apikey' : KEY}
                response = requests.post(VIRUSTOTAL_URL_RESUMBIT, data=data)
            except Exception as e:
                print_error("Failed Submit: {0}".format(e))
                return

            try:
                virustotal = response.json()
            except Exception as e:
                print_error("Unable to parse response: {0}".format(e))
                print_error("Data:\n{}".format(response.content))
                return

            if 'verbose_msg' in virustotal:
                print_info("{}: {}".format(bold("VirusTotal message"), virustotal['verbose_msg']))

        def submit(file_path):
            try:
                data = {'apikey' : KEY}
                files = {'file' : open(file_path, 'rb').read()}
                response = requests.post(VIRUSTOTAL_URL_SUBMIT, data=data, files=files)
            except Exception as e:
                print_error("Failed Submit: {0}".format(e))
                return

            try:
                virustotal = response.json()
            except Exception as e:
                print_error("Unable to parse response: {0}".format(e))
                print_error("Data:\n{}".format(response.content))
                return

            if 'verbose_msg' in virustotal:
                print_info("{}: {}".format(bold("VirusTotal message"), virustotal['verbose_msg']))

        def help():
            usage()
            print("")
            print("Options:")
            print("\t--help (-h)\tShow this help message")
            print("\t--submit (-s)\tSubmit file to VirusTotal (by default it only looks up the hash)")
            print("\t--resubmit (-r)\tRescan file in VirusTotal")
            print("\t--scan (-n)\tScan the repository)")
            print("\t--engine (-e)\tOutput scan result with signature for AV engine)")
            print("")

        try:
            opts, argv = getopt.getopt(self.args[0:], 'hsnre:', ['help', 'submit', 'scan', 'resubmit', 'engine='])
        except getopt.GetoptError as e:
            print(e)
            return

        arg_av = ''
        for opt, value in opts:
            if opt in ('-h', '--help'):
                help()
                return
            elif opt in ('-n', '--scan'):
                self.arg_scan = True
            if opt in ('-e', '--engine'):
                arg_av = str(value)
            if opt in ('-s', '--submit'):
                self.arg_submit = True
            if opt in ('-r', '--resubmit'):
                self.arg_resubmit = True

        if not HAVE_REQUESTS:
            print_error("Missing dependency, install requests (`pip install requests`)")
            return

        if self.arg_scan:
            print_info("Scanning the repository ...")

            # Retrieve list of samples stored locally and available in the
            # database.
            db = Database()
            samples = db.find(key='all')
            matches = []
            av_engine = ''
            for sample in samples:
                av_signature = ''
                data = {'resource' : sample.md5, 'apikey' : KEY}
                print_info("Checking file \"{0}\" ...".format(sample.name))
                time.sleep(TIMER)
                try:
                    response = requests.post(VIRUSTOTAL_URL, data=data)
                except Exception as e:
                    print_error("Failed performing request: {0}".format(e))
                    return

                try:
                    virustotal = response.json()
                except Exception as e:
                    print_error("Failed parsing the response: {0}".format(e))
                    print_error("Data:\n{}".format(response.content))
                    break

                if virustotal['response_code']:
                    result = "{} / {}".format(virustotal['positives'], virustotal['total'])
                    if len(arg_av) > 0:
                        for engine, signature in virustotal['scans'].items():
                            if arg_av == engine:
                                av_engine = engine
                                if signature['detected']:
                                    av_signature = signature['result']
                                else:
                                    av_signature = 'Not detected'

                                break

                    if self.arg_resubmit:
                        print_info("Resubmit file \"{0}\" ...".format(sample.name))
                        resubmit(sample.md5)
                else:
                    result = 'NULL'
                    if self.arg_submit:
                        sample_path = get_sample_path(sample.sha256)
                        print_info("Submit file \"{0}\" ...".format(sample.name))
                        submit(sample_path)

                if len(arg_av) == 0:
                    matches.append([sample.name, result])
                else:
                    matches.append([sample.name, av_signature, result])

            if len(arg_av) > 0:
                print(table(header=['Name', av_engine, 'Scan'], rows=matches))
                if len(av_engine) == 0:
                    print_error("AV engine not found\n")
            else:
                print(table(header=['Name', 'Scan'], rows=matches))

        else:
            if not __sessions__.is_set():
                print_error("No session opened")
                return

            report()
            if self.arg_submit:
                submit(__sessions__.current.file.path)
            elif self.arg_resubmit:
                resubmit(__sessions__.current.file.md5)


