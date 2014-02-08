# Copyright (C) 2013-2014 Claudio "nex" Guarnieri.
# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os
import json
import urllib
import urllib2

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __session__

VIRUSTOTAL_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
KEY = 'a0283a2c3d55728300d064874239b5346fb991317e8449fe43c902879d758088'

class VirusTotal(Module):
    cmd = 'virustotal'
    description = 'Lookup the file on VirusTotal'

    def run(self):
        if not __session__.is_set():
            print_error("No session opened")
            return

        data = urllib.urlencode({'resource' : __session__.file.md5, 'apikey' : KEY})

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

        print(table(['Antivirus', 'Signature'], rows))
