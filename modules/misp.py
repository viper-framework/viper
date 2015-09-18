# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import argparse
import copy
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
from viper.core.database import Database
from viper.core.session import __sessions__
from viper.core.storage import get_sample_path
from viper.common.objects import MispEvent
from viper.common.constants import VIPER_ROOT

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
        parser_up.add_argument("-e", "--event", type=int, help="Event ID to update. If None, and you're not connected to a MISP event a new one is created.")
        parser_up.add_argument("-d", "--distrib", type=int, choices=[0, 1, 2, 3], help="Distribution of the attributes for the new event.")
        parser_up.add_argument("-ids", action='store_true', help="Is eligible for automatically creating IDS signatures.")
        parser_up.add_argument("-c", "--categ", type=int, choices=[0, 1, 2, 3], default=1, help="Category of the samples.")
        parser_up.add_argument("-i", "--info", nargs='+', help="Event info field of a new event.")
        parser_up.add_argument("-a", "--analysis", type=int, choices=[0, 1, 2], help="Analysis level a new event.")
        parser_up.add_argument("-t", "--threat", type=int, choices=[0, 1, 2, 3], help="Threat level of a new event.")

        parser_down = subparsers.add_parser('download', help='Download malware samples from MISP.')
        group = parser_down.add_mutually_exclusive_group()
        group.add_argument("-e", "--event", type=int, help="Download all the samples related to this event ID.")
        group.add_argument("--hash", help="Download the sample related to this hash (only MD5).")

        parser_search = subparsers.add_parser('search', help='Search in all the attributes.')
        parser_search.add_argument("query", nargs='+', help="String to search.")

        parser_checkhashes = subparsers.add_parser('check_hashes', help='Crosscheck hashes on VT.')
        parser_checkhashes.add_argument("event", help="Lookup all the hashes of an event on VT.")
        parser_checkhashes.add_argument("-p", "--populate", action='store_true', help="Automatically populate event with hashes found on VT.")

        parser_checkhashes = subparsers.add_parser('yara', help='Get YARA rules of an event.')
        parser_checkhashes.add_argument("event", help="Download the yara rules of that event.")

        parser_get_event = subparsers.add_parser('get_event', help='Initialize the session with an existing MISP event.')
        parser_get_event.add_argument("event", help="Existing Event ID.")

        parser_create_event = subparsers.add_parser('create_event', help='Create a new event on MISP and initialize the session with it.')
        parser_create_event.add_argument("-d", "--distrib", required=True, type=int, choices=[0, 1, 2, 3], help="Distribution of the attributes for the new event.")
        parser_create_event.add_argument("-t", "--threat", required=True, type=int, choices=[0, 1, 2, 3], help="Threat level of a new event.")
        parser_create_event.add_argument("-a", "--analysis", required=True, type=int, choices=[0, 1, 2], help="Analysis level a new event.")
        parser_create_event.add_argument("-i", "--info", required=True, nargs='+', help="Event info field of a new event.")
        parser_create_event.add_argument("--date", help="Date of the event. (Default: today).")

        parser_add = subparsers.add_parser('add', help='Add attributes to an existing MISP event.')
        subparsers_add = parser_add.add_subparsers(dest='add')
        h = subparsers_add.add_parser("hashes", help="If no parameters, add add all the hashes of the current session.")
        h.add_argument("-f", "--filename", help="Filename")
        h.add_argument("-m", "--md5", help="MD5")
        h.add_argument("-s", "--sha1", help="SHA1")
        h.add_argument("-a", "--sha256", help="SHA256")

        rk = subparsers_add.add_parser("regkey", help="Add a registry key to the event.")
        rk.add_argument("regkey", nargs='+', help="First word is the key, second word (optional) is the value: <key> <value>")

        pipe = subparsers_add.add_parser("pipe", help="Add a pipe to the event.")
        pipe.add_argument("pipe", help='Name of the pipe.')

        mutex = subparsers_add.add_parser("mutex", help="Add a mutex to the event.")
        mutex.add_argument("mutex", help='Name of the mutex.')

        ipdst = subparsers_add.add_parser("ipdst", help="Add a destination IP (C&C Server) to the event.")
        ipdst.add_argument("ipdst", help='IP address')

        hostname = subparsers_add.add_parser("hostname", help="Add an hostname to the event.")
        hostname.add_argument("hostname", help='Hostname')

        domain = subparsers_add.add_parser("domain", help="Add a domain to the event.")
        domain.add_argument("domain", help='Domain')

        url = subparsers_add.add_parser("url", help="Add a URL to the event.")
        url.add_argument("full_url", help='URL')

        ua = subparsers_add.add_parser("ua", help="Add a user-agent to the event.")
        ua.add_argument("ua", help='User Agent')

        pfile = subparsers_add.add_parser("pattern_file", help="Add a pattern in file to the event.")
        pfile.add_argument("pfile", help='Pattern in file')

        pmem = subparsers_add.add_parser("pattern_mem", help="Add a pattern in memory to the event.")
        pmem.add_argument("pmem", help='Pattern in memory')

        ptraffic = subparsers_add.add_parser("pattern_traffic", help="Add a  to the event.")
        ptraffic.add_argument("ptraffic", help='Pattern in traffic')

        subparsers.add_parser('show', help='Show attributes to an existing MISP event.')

        subparsers.add_parser('publish', help='Publish an existing MISP event.')

        subparsers.add_parser('version', help='Returns the version of the MISP instance.')

        self.categories = {0: 'Payload delivery', 1: 'Artifacts dropped', 2: 'Payload installation', 3: 'External analysis'}

    def yara(self):
        ok = False
        data = None
        if self.args.event:
            ok, data = self.misp.get_yara(self.args.event)
        if not ok:
            self.log('error', data)
            return
        rule_path = os.path.join(VIPER_ROOT, 'data/yara', self.args.event + '.yara')
        if os.path.exists(rule_path):
            self.log('error', 'File {} already exists.'.format(rule_path))
            return
        with open(rule_path, 'wb') as f:
            f.write(data.encode('utf-8'))
        self.log('success', 'The yara rules of event {} have been downloaded: {}'.format(self.args.event, rule_path))

    def download(self):
        ok = False
        data = None
        if self.args.event:
            ok, data = self.misp.download_samples(event_id=self.args.event)
        elif self.args.hash:
            ok, data = self.misp.download_samples(sample_hash=self.args.hash)
        else:
            # Download from current MISP event if possible
            if not __sessions__.is_set():
                self.log('error', "No session opened")
                return False
            if not __sessions__.current.misp_event:
                self.log('error', "Not connected to a MISP event.")
                return False
            ok, data = self.misp.download_samples(event_id=__sessions__.current.misp_event.event_id)

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
            self.log('success', 'The sample has been downloaded from Event {}'.format(to_print[0][0]))
            event = self.misp.get_event(to_print[0][0])
            return __sessions__.new(to_print[0][1], MispEvent(event.json()))
        else:
            self.log('success', 'The following files have been downloaded:')
            for p in to_print:
                self.log('success', '\tEventID: {} - {}'.format(*p))

    def upload(self):
        if not __sessions__.is_set():
            self.log('error', "No session opened")
            return False

        categ = self.categories.get(self.args.categ)
        if self.args.info is not None:
            info = ' '.join(self.args.info)
        else:
            info = None
        if self.args.event is not None:
            event = self.args.event
        elif __sessions__.current.misp_event is not None:
            event = __sessions__.current.misp_event.event_id
        else:
            event = None
        try:
            out = self.misp.upload_sample(__sessions__.current.file.name, __sessions__.current.file.path,
                                          event, self.args.distrib, self.args.ids, categ, info,
                                          self.args.analysis, self.args.threat)
        except Exception as e:
            self.log('error', e)
            return
        result = out.json()
        if out.status_code == 200:
            if result.get('errors') is not None:
                self.log('error', result.get('errors')[0]['error']['value'][0])
            else:
                self.log('success', "File uploaded sucessfully")
                if event is None:
                    event = result.get('id')
                if event is not None:
                    full_event = self.misp.get_event(event)
                    return __sessions__.new(misp_event=MispEvent(full_event.json()))
        else:
            self.log('error', result.get('message'))

    def search_local_hashes(self, event):
        local = []
        samples_count = 0
        for a in event['Event']['Attribute']:
            row = None
            if a['type'] == 'malware-sample':
                samples_count += 1
            if a['type'] in ('malware-sample', 'filename|md5', 'md5'):
                h = a['value']
                if '|' in a['type']:
                    h = a['value'].split('|')[1]
                row = Database().find(key='md5', value=h)
            elif a['type'] in ('sha1', 'filename|sha1'):
                h = a['value']
                if '|' in a['type']:
                    h = a['value'].split('|')[1]
                row = Database().find(key='sha1', value=h)
            elif a['type'] in ('sha256', 'filename|sha256'):
                h = a['value']
                if '|' in a['type']:
                    h = a['value'].split('|')[1]
                row = Database().find(key='sha256', value=h)
            if row:
                local.append(row[0])
        self.log('info', 'This event contains {} samples.'.format(samples_count))
        shas = set([l.sha256 for l in local])
        if len(shas) == 1:
            __sessions__.new(get_sample_path(shas.pop()), MispEvent(event))
        elif len(shas) > 1:
            self.log('success', 'The following samples are in this viper instance:')
            __sessions__.new(misp_event=MispEvent(event))
            for s in shas:
                self.log('item', s)
        else:
            __sessions__.new(misp_event=MispEvent(event))
            self.log('info', 'No known (in Viper) samples in that event.')

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
                                          "comment": '{} - Xchecked via VT: {}'.format(a["comment"].encode('utf-8'), h),
                                          "to_ids": a["to_ids"],
                                          "distribution": a["distribution"]}

        unk_vt_hashes = []
        attributes = []
        vt_request = {'apikey': VT_KEY}
        # Make sure to start getting reports for the longest possible hashes (reduce risks of collisions)
        hashes_to_check = sorted(event_hashes, key=len)
        while len(hashes_to_check) > 0:
            vt_request['resource'] = hashes_to_check.pop()
            try:
                response = requests.post(VT_REPORT_URL, data=vt_request)
            except requests.ConnectionError:
                self.log('error', 'Failed to connect to VT for {}'.format(vt_request['resource']))
                return
            if response.status_code == 403:
                self.log('error', 'This command requires virustotal API key')
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
                link = [False, result['permalink']]
                # Do not re-add a link
                for a in event['Attribute']:
                    if a['value'] == link[1]:
                        link[0] = True
                if md5 in sample_hashes:
                    self.log('success', 'Sample available in MISP:')
                else:
                    self.log('success', 'Sample available in VT:')
                if self.args.populate:
                    attributes += self._prepare_attributes(md5, sha1, sha256, link, base_new_attributes, event_hashes, sample_hashes)
                self.log('item', '{}\n\t{}\n\t{}\n\t{}'.format(link[1], md5, sha1, sha256))
            else:
                unk_vt_hashes.append(vt_request['resource'])

        if self.args.populate:
            self._populate(event, attributes)
        if len(unk_vt_hashes) > 0:
            self.log('error', 'Unknown on VT:')
            for h in unk_vt_hashes:
                self.log('item', '{}'.format(h))

    def _prepare_attributes(self, md5, sha1, sha256, link, base_attr, event_hashes, sample_hashes):
        new_md5 = False
        new_sha1 = False
        new_sha256 = False
        if md5 not in event_hashes and md5 not in sample_hashes:
            new_md5 = True
        if sha1 not in event_hashes:
            new_sha1 = True
        if sha256 not in event_hashes:
            new_sha256 = True

        curattr = None
        if base_attr.get(sha256):
            curattr = base_attr.get(sha256)
        elif base_attr.get(sha1):
            curattr = base_attr.get(sha1)
        else:
            curattr = base_attr.get(md5)

        attibutes = []
        if new_sha256:
            attibutes.append(dict(curattr, **{'type': 'sha256', 'value': sha256}))
        if new_sha1:
            attibutes.append(dict(curattr, **{'type': 'sha1', 'value': sha1}))
        if new_md5:
            attibutes.append(dict(curattr, **{'type': 'md5', 'value': md5}))

        distrib = curattr['distribution']
        if not link[0]:
            attibutes.append({'type': 'link', 'category': 'External analysis',
                              'distribution': distrib, 'value': link[1]})
        return attibutes

    def _populate(self, event, attributes):
        if len(attributes) == 0:
            self.log('info', "No new attributes to add.")
            return
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
        result = self.misp.search_all(' '.join(self.args.query))

        if result.get('response') is None:
            self.log('error', result.get('message'))
            return
        self.log('success', 'Found the following events:')
        for e in result['response']:
            nb_samples = 0
            nb_hashes = 0
            for a in e['Event']['Attribute']:
                if a.get('type') == 'malware-sample':
                    nb_samples += 1
                if a['type'] in ('md5', 'sha1', 'sha256', 'filename|md5',
                                 'filename|sha1', 'filename|sha256'):
                    nb_hashes += 1
            self.log('item', '{} ({} samples, {} hashes) - {}{}{}'.format(
                e['Event']['info'].encode('utf-8'), nb_samples, nb_hashes, self.url, '/events/view/', e['Event']['id']))

    def get_event(self):
        event = self.misp.get_event(self.args.event)
        event_dict = event.json()
        self.search_local_hashes(event_dict)

    def create_event(self):
        # Dirty trick to keep consistency in the module: the threat level in the upload
        # API can go from 0 import to 3 but it is 1 to 4 in the event mgmt API.
        # It will be fixed in a near future, in the mean time, we do that:
        self.args.threat += 1

        event = self.misp.new_event(self.args.distrib, self.args.threat, self.args.analysis,
                                    ' '.join(self.args.info), self.args.date)
        self.search_local_hashes(event)

    def _find_related_id(self, event):
        if not event.get('RelatedEvent'):
            return []
        related = []
        for events in event.get('RelatedEvent'):
            for info in events['Event']:
                related.append(info['id'])
        return list(set(related))

    def _check_add(self, new_event):
        if not new_event.get('Event'):
            self.log('error', new_event)
            return
        old_related = self._find_related_id(__sessions__.current.misp_event.event.get('Event'))
        new_related = self._find_related_id(new_event.get('Event'))
        for related in new_related:
            if related not in old_related:
                self.log('success', 'New related event: {}/{}'.format(self.url.rstrip('/'), related))
            else:
                self.log('info', 'Related event: {}/{}'.format(self.url.rstrip('/'), related))
        __sessions__.new(misp_event=MispEvent(new_event))

    def publish(self):
        if not __sessions__.is_set():
            self.log('error', "No session opened")
            return False
        if not __sessions__.current.misp_event:
            self.log('error', "Not attached to a MISP event")
            return False

        current_event = copy.deepcopy(__sessions__.current.misp_event.event)
        event = self.misp.publish(current_event)
        if not event.get('Event'):
            self.log('error', event['message'])
            return
        self.log('success', 'Event {} published.'.format(event['Event']['id']))

    def show(self):
        if not __sessions__.is_set():
            self.log('error', "No session opened")
            return False
        if not __sessions__.current.misp_event:
            self.log('error', "Not attached to a MISP event")
            return False

        current_event = copy.deepcopy(__sessions__.current.misp_event.event)

        header = ['type', 'value', 'comment']
        rows = []
        for a in current_event['Event']['Attribute']:
            rows.append([a['type'], a['value'], a['comment']])
        if current_event['Event']['published']:
            self.log('info', 'This event has been published')
        else:
            self.log('info', 'This event has not been published')
        self.log('table', dict(header=header, rows=rows))

    def add(self):
        if not __sessions__.is_set():
            self.log('error', "No session opened")
            return False
        if not __sessions__.current.misp_event:
            self.log('error', "Not attached to a MISP event")
            return False

        current_event = copy.deepcopy(__sessions__.current.misp_event.event)

        if self.args.add == 'hashes':
            if self.args.filename is None and self.args.md5 is None and self.args.sha1 is None and self.args.sha256 is None:
                if not __sessions__.current.file:
                    self.log('error', "Not attached to a file, please set the hashes manually.")
                    return False
                event = self.misp.add_hashes(current_event, filename=__sessions__.current.file.name,
                                             md5=__sessions__.current.file.md5, sha1=__sessions__.current.file.sha1,
                                             sha256=__sessions__.current.file.sha256,
                                             comment=__sessions__.current.file.tags)
            else:
                event = self.misp.add_hashes(current_event, filename=self.args.filename,
                                             md5=self.args.md5, sha1=self.args.sha1, sha256=self.args.sha256)
            self._check_add(event)
        elif self.args.add == 'regkey':
            if len(self.args.regkey) == 2:
                reg, val = self.args.regkey
            else:
                reg = self.args.regkey[0]
                val = None
            event = self.misp.add_regkey(current_event, reg, val)
            self._check_add(event)
        elif self.args.add == 'pipe':
            event = self.misp.add_pipe(current_event, self.args.pipe)
            self._check_add(event)
        elif self.args.add == 'mutex':
            event = self.misp.add_mutex(current_event, self.args.mutex)
            self._check_add(event)
        elif self.args.add == 'ipdst':
            event = self.misp.add_ipdst(current_event, self.args.ipdst)
            self._check_add(event)
        elif self.args.add == 'hostname':
            event = self.misp.add_hostname(current_event, self.args.hostname)
            self._check_add(event)
        elif self.args.add == 'domain':
            event = self.misp.add_domain(current_event, self.args.domain)
            self._check_add(event)
        elif self.args.add == 'url':
            event = self.misp.add_url(current_event, self.args.full_url)
            self._check_add(event)
        elif self.args.add == 'ua':
            event = self.misp.add_useragent(current_event, self.args.ua)
            self._check_add(event)
        elif self.args.add == 'pattern_file':
            event = self.misp.add_pattern(current_event, self.args.pfile, True, False)
            self._check_add(event)
        elif self.args.add == 'pattern_mem':
            event = self.misp.add_pattern(current_event, self.args.pmem, False, True)
            self._check_add(event)
        elif self.args.add == 'pattern_traffic':
            event = self.misp.add_traffic_pattern(current_event, self.args.ptraffic)
            self._check_add(event)

    def version(self):
        ok = True
        api_version = self.misp.get_api_version()
        self.log('info', 'The version of your MISP API is: {}'.format(api_version['version']))
        api_version_master = self.misp.get_api_version_master()
        if api_version_master.get('version') is None:
            ok = False
            self.log('error', api_version_master)
        else:
            self.log('info', 'The version of MISP API master branch is: {}'.format(api_version_master['version']))

        misp_version = self.misp.get_version()
        if misp_version.get('version') is None:
            ok = False
            self.log('error', misp_version)
        else:
            self.log('info', 'The version of your MISP instance is: {}'.format(misp_version['version']))

        misp_version_master = self.misp.get_version_master()
        if misp_version_master.get('version') is None:
            ok = False
            self.log('error', misp_version_master)
        else:
            self.log('info', 'The version of MISP master branch is: {}'.format(misp_version_master['version']))

        if not ok:
            return

        if misp_version['version'] == misp_version_master['version']:
            self.log('success', 'Congratulation, your MISP instance is up-to-date')
        else:
            self.log('warning', 'Your MISP instance is outdated, you should update to avoid issues with the API.')

        if api_version['version'] == api_version_master['version']:
            self.log('success', 'Congratulation, the MISP API installed is up-to-date')
        else:
            self.log('warning', 'The MISP API installed is outdated, you should update to avoid issues.')

    def run(self):
        super(MISP, self).run()
        if self.args is None:
            return

        if not HAVE_PYMISP:
            self.log('error', "Missing dependency, install pymisp (`pip install pymisp`)")
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
        elif self.args.subname == 'yara':
            self.yara()
        elif self.args.subname == 'get_event':
            self.get_event()
        elif self.args.subname == 'create_event':
            self.create_event()
        elif self.args.subname == 'add':
            self.add()
        elif self.args.subname == 'show':
            self.show()
        elif self.args.subname == 'publish':
            self.publish()
        elif self.args.subname == 'version':
            self.version()
        else:
            self.log('error', "No calls defined for this command.")
