# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import argparse
import textwrap
import os
import tempfile

try:
    from pymisp import PyMISP
    HAVE_PYMISP = True
except:
    HAVE_PYMISP = False

from viper.common.abstracts import Module
from viper.core.session import __sessions__

MISP_URL = ''
MISP_KEY = ''


class MISP(Module):
    cmd = 'misp'
    description = 'Upload and query IOCs to/from a MISP instance'
    authors = ['Raphaël Vinot']

    def __init__(self):
        super(MISP, self).__init__()
        self.parser.add_argument("--url", help='URL of the MISP instance')
        self.parser.add_argument("-k", "--key", help='Your key on the MISP instance')
        subparsers = self.parser.add_subparsers(dest='subname')

        parser_up = subparsers.add_parser('upload', help='Send malware sample to MISP.', formatter_class=argparse.RawDescriptionHelpFormatter,
                                          description=textwrap.dedent('''
                                            Distribution levels:
                                                * 0: Your organisation only
                                                * 1: This community only
                                                * 2: Connected communities
                                                * 3: All communities

                                            Sample categories:
                                                * 0: Payload delivery
                                                * 1: Artifacts dropped
                                                * 2: Payload installation
                                                * 3: External analysis

                                            Analysis levels:
                                                * 0: Initial
                                                * 1: Ongoing
                                                * 2: Completed

                                            Threat levels:
                                                * 0: High
                                                * 1: Medium
                                                * 2: Low
                                                * 3: Undefined

                                          '''))
        parser_up.add_argument("-e", "--event", type=int, help="Event ID to update. If None, a new event is created.")
        parser_up.add_argument("-d", "--distrib", type=int, choices=[0, 1, 2, 3], help="Distribution of the attributes for the new event.")
        parser_up.add_argument("-ids", action='store_true', help="Is eligible for automatically creating IDS signatures.")
        parser_up.add_argument("-c", "--categ", type=int, choices=[0, 1, 2, 3], help="Category of the samples.")
        parser_up.add_argument("-i", "--info", help="Event info field of a new event.")
        parser_up.add_argument("-a", "--analysis", type=int, choices=[0, 1, 2], help="Analysis level a new event.")
        parser_up.add_argument("-t", "--threat", type=int, choices=[0, 1, 2, 3], help="Threat level of a new event.")

        parser_down = subparsers.add_parser('download', help='Download malware samples from MISP.')
        group = parser_down.add_mutually_exclusive_group(required=True)
        group.add_argument("-e", "--event", type=int, help="Download all the samples related to this event ID.")
        group.add_argument("--hash", help="Download the sample related to this hash (only MD5).")

        parser_search = subparsers.add_parser('search', help='Search in all the attributes.')
        parser_search.add_argument("-q", "--query", required=True, help="String to search.")

        self.categories = {0: 'Payload delivery', 1: 'Artifacts dropped', 2: 'Payload installation', 3: 'External analysis'}

    def download(self):
        ok = False
        data = None
        if self.args.event:
            ok, data = self.misp.download_samples(event_id=self.args.event)
        elif self.args.hash:
            ok, data = self.misp.download_samples(sample_hash=self.args.hash)
        if not ok:
            self.log('error', data)
            return
        to_print = []
        for d in data:
            eid, filename, payload = d
            path = os.path.join(tempfile.gettempdir(), filename)
            with open(path, 'w') as f:
                f.write(payload.getvalue())
            to_print.append((eid, path))

        if len(to_print) == 1:
            return __sessions__.new(to_print[0][1])
        else:
            self.log('success', 'The following files have been downloaded:')
            for p in to_print:
                self.log('success', '\tEventID: {} - {}'.format(*p))

    def upload(self):
        if not __sessions__.is_set():
            self.log('error', "No session opened")
            return False

        categ = self.categories.get(self.args.categ)
        out = self.misp.upload_sample(__sessions__.current.file.name, __sessions__.current.file.path,
                                      self.args.event, self.args.distrib, self.args.ids, categ,
                                      self.args.info, self.args.analysis, self.args.threat)
        if out.status_code == 200:
            self.log('success', "File uploaded sucessfully")
        else:
            result = out.json()
            self.log('error', result.get('message'))

    def searchall(self):
        result = self.misp.search_all(self.args.query)

        if result.get('response') is None:
            self.log('error', result.get('message'))
            return
        self.log('success', 'Found the following events:')
        for e in result['response']:
            self.log('success', '\t{}{}{}'.format(self.url, '/events/view/', e['Event']['id']))

    def run(self):
        super(MISP, self).run()
        if self.args is None:
            return

        if not HAVE_PYMISP:
            self.log('error', "Missing dependency, install requests (`pip install pymisp`)")
            return

        if self.args.url is None:
            self.url = MISP_URL
        else:
            self.url = self.args.url

        if self.args.key is None:
            self.key = MISP_KEY
        else:
            self.key = self.args.key

        if self.url is None:
            self.log('error', "This command requires the URL of the MISP instance you want to query.")
            return
        if self.key is None:
            self.log('error', "This command requires a MISP private API key.")
            return

        self.misp = PyMISP(self.url, self.key, True, 'json')

        if self.args.subname == 'upload':
            self.upload()
        elif self.args.subname == 'search':
            self.searchall()
        elif self.args.subname == 'download':
            self.download()
