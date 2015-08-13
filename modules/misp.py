# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import argparse
import textwrap
import os
import tempfile
import time

try:
    from pymisp import PyMISP
    HAVE_PYMISP = True
except:
    HAVE_PYMISP = False

try:
    import requests
    HAVE_REQUESTS = True
except:
    HAVE_REQUESTS = False


from viper.common.abstracts import Module
from viper.core.session import __sessions__

MISP_URL = ''
MISP_KEY = ''

VT_REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
VT_DOWNLOAD_URL = 'https://www.virustotal.com/vtapi/v2/file/download'
VT_KEY = ''


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

        parser_checkhashes = subparsers.add_parser('check_hashes', help='Crosscheck hashes on VT.')
        parser_checkhashes.add_argument("-e", "--event", required=True, help="Lookup all the hashes of an event on VT.")
        parser_checkhashes.add_argument("-p", "--populate", action='store_true', help="Automatically populate event with hashes found on VT.")

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
        result = out.json()
        if out.status_code == 200:
            if result.get('errors') is not None:
                self.log('error', result.get('errors')[0]['error']['value'][0])
            else:
                self.log('success', "File uploaded sucessfully")
        else:
            self.log('error', result.get('message'))

    def check_hashes(self):
        out = self.misp.get_event(self.args.event)
        result = out.json()
        if out.status_code != 200:
            self.log('error', result.get('message'))
            return

        event = result.get('Event')
        event_hashes = []
        sample_hashes = []
        base_new_attributes = {}
        for a in event['Attribute']:
            h = None
            if a['type'] in ('md5', 'sha1', 'sha256'):
                h = a['value']
                event_hashes.append(h)
            elif a['type'] in ('filename|md5', 'filename|sha1', 'filename|sha256'):
                h = a['value'].split('|')[1]
                event_hashes.append(h)
            elif a['type'] == 'malware-sample':
                h = a['value'].split('|')[1]
                sample_hashes.append(h)
            if h is not None:
                base_new_attributes[h] = {"category": a["category"],
                                          "comment": '{} - Xchecked via VT: {}'.format(a["comment"], h),
                                          "to_ids": a["to_ids"],
                                          "distribution": a["distribution"]}

        vt_hashes = {}
        unk_vt_hashes = []
        vt_request = {'apikey': VT_KEY}
        hashes_to_check = event_hashes
        while len(hashes_to_check) > 0:
            vt_request['resource'] = hashes_to_check.pop()
            response = requests.post(VT_REPORT_URL, data=vt_request)
            if response.status_code == 403:
                self.log('error', 'This command requires virustotal private API key')
                self.log('error', 'Please check that your key have the right permissions')
                return
            try:
                result = response.json()
            except:
                # FIXME: support rate-limiting (4/min)
                self.log('error', 'Unable to get the report of {}'.format(vt_request['resource']))
                continue
            if result['response_code'] == 1:
                md5 = result['md5']
                sha1 = result['sha1']
                sha256 = result['sha256']
                hashes_to_check = [eh for eh in hashes_to_check if eh not in (md5, sha1, sha256)]
                link = result['permalink']
                vt_hashes[md5] = (sha1, sha256, link)
            else:
                unk_vt_hashes.append(vt_request['resource'])

        if self.args.populate:
            attributes = []

        for md5 in vt_hashes.keys():
            sha1, sha256, link = vt_hashes.get(md5)
            if md5 in sample_hashes:
                self.log('success', 'Sample available in MISP:')
            else:
                self.log('success', 'Sample available in VT:')
                if self.args.populate:
                    attributes += self._prepare_attributes(md5, sha1, sha256, link, base_new_attributes, event_hashes)
            self.log('success', '\t{}\n\t\t{}\n\t\t{}\n\t\t{}'.format(link, md5, sha1, sha256))
        if self.args.populate:
            self._populate(event, attributes)
        if len(unk_vt_hashes) > 0:
            self.log('error', 'Unknown on VT:')
            for h in unk_vt_hashes:
                self.log('error', '\t {}'.format(h))

    def _prepare_attributes(self, md5, sha1, sha256, link, base_attr, event_hashes):
        attibutes = []
        new_md5 = False
        new_sha1 = False
        new_sha256 = False
        if md5 not in event_hashes:
            new_md5 = True
        if sha1 not in event_hashes:
            new_sha1 = True
        if sha256 not in event_hashes:
            new_sha256 = True
        if base_attr.get(md5):
            if new_sha1:
                attibutes.append(dict(base_attr.get(md5), **{'type': 'sha1', 'value': sha1}))
            if new_sha256:
                attibutes.append(dict(base_attr.get(md5), **{'type': 'sha256', 'value': sha256}))
            distrib = base_attr.get(md5)['distribution']
        elif base_attr.get(sha1):
            if new_md5:
                attibutes.append(dict(base_attr.get(sha1), **{'type': 'md5', 'value': md5}))
            if new_sha256:
                attibutes.append(dict(base_attr.get(sha1), **{'type': 'sha256', 'value': sha256}))
            distrib = base_attr.get(sha1)['distribution']
        else:
            if new_md5:
                attibutes.append(dict(base_attr.get(sha256), **{'type': 'md5', 'value': md5}))
            if new_sha1:
                attibutes.append(dict(base_attr.get(sha256), **{'type': 'sha1', 'value': sha1}))
            distrib = base_attr.get(sha256)['distribution']
        attibutes.append({'type': 'link', 'category': 'External analysis',
                          'distribution': distrib, 'value': link})
        return attibutes

    def _populate(self, event, attributes):
        to_send = {'Event': {'id': int(event['id']), 'uuid': event['uuid'],
                             'date': event['date'], 'distribution': event['distribution'],
                             'threat_level_id': event['threat_level_id'],
                             'analysis': event['analysis'], 'Attribute': attributes,
                             'timestamp': int(time.time())}}
        out = self.misp.update_event(int(event['id']), to_send)
        result = out.json()
        if out.status_code == 200:
            if result.get('message') is not None:
                self.log('error', result.get('message'))
            elif result.get('errors') is not None:
                for e in result.get('errors'):
                    self.log('error', e['error']['value'][0])
            else:
                self.log('success', "All attributes updated sucessfully")
        else:
            self.log('error', result.get('message'))

    def searchall(self):
        result = self.misp.search_all(self.args.query)

        if result.get('response') is None:
            self.log('error', result.get('message'))
            return
        self.log('success', 'Found the following events:')
        for e in result['response']:
            nb_samples = 0
            for a in e['Event']['Attribute']:
                if a.get('type') == 'malware-sample':
                    nb_samples += 1
            self.log('success', '\t{} ({} samples) - {}{}{}'.format(e['Event']['info'], nb_samples, self.url, '/events/view/', e['Event']['id']))

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
        elif self.args.subname == 'check_hashes':
            self.check_hashes()
