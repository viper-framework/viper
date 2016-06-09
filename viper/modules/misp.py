# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import argparse
import copy
import textwrap
import os
import time
import glob
import shutil
import json

try:
    from pymisp import PyMISP, PyMISPError
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
from viper.core.project import __project__
from viper.core.storage import get_sample_path
from viper.common.objects import MispEvent
from viper.common.constants import VIPER_ROOT
from viper.core.config import Config

cfg = Config()


class MISP(Module):
    cmd = 'misp'
    description = 'Upload and query IOCs to/from a MISP instance'
    authors = ['Raphaël Vinot']

    def __init__(self):
        super(MISP, self).__init__()
        self.cur_path = __project__.get_path()
        self.parser.add_argument("--url", help='URL of the MISP instance')
        self.parser.add_argument("-k", "--key", help='Your key on the MISP instance')
        self.parser.add_argument("-v", "--verify", action='store_false', help='Disable certificate verification (for self-signed)')
        subparsers = self.parser.add_subparsers(dest='subname')

        # ##### Upload sample to MISP #####
        parser_up = subparsers.add_parser('upload', help='Send malware sample to MISP.',
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
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
        parser_up.add_argument("-o", "--comment", nargs='+', help="Comment associated to the sample.")
        parser_up.add_argument("-a", "--analysis", type=int, choices=[0, 1, 2], help="Analysis level a new event.")
        parser_up.add_argument("-t", "--threat", type=int, choices=[0, 1, 2, 3], help="Threat level of a new event.")

        # ##### Download samples from event #####
        parser_down = subparsers.add_parser('download', help='Download malware samples from MISP.')
        group = parser_down.add_mutually_exclusive_group()
        group.add_argument("-e", "--event", type=int, help="Download all the samples related to this event ID.")
        group.add_argument("-l", "--list", nargs='*', help="Download all the samples related to a list of events. Empty list to download all the samples of all the events stored in the current project.")
        group.add_argument("--hash", help="Download the sample related to this hash (only MD5).")

        # ##### Search in MISP #####
        parser_search = subparsers.add_parser('search', help='Search in all the attributes.')
        parser_search.add_argument("query", nargs='*', help="String to search (if empty, search the hashes of the current file).")

        # ##### Check hashes on VT #####
        parser_checkhashes = subparsers.add_parser('check_hashes', help='Crosscheck hashes on VT.')
        parser_checkhashes.add_argument("event", nargs='?', default=None, type=int, help="Lookup all the hashes of an event on VT.")
        parser_checkhashes.add_argument("-p", "--populate", action='store_true', help="Automatically populate event with hashes found on VT.")

        # ##### Download Yara rules #####
        parser_checkhashes = subparsers.add_parser('yara', help='Get YARA rules of an event.')
        parser_checkhashes.add_argument("event", nargs='?', default=None, type=int, help="Download the yara rules of that event.")

        # ##### Get Events #####
        parser_pull = subparsers.add_parser('pull', help='Initialize the session with an existing MISP event.')
        parser_pull.add_argument("event", nargs='+', type=int, help="(List of) Event(s) ID.")

        # ##### Create an Event #####
        parser_create_event = subparsers.add_parser('create_event', help='Create a new event on MISP and initialize the session with it.',
                                                    formatter_class=argparse.RawDescriptionHelpFormatter,
                                                    description=textwrap.dedent('''
                                                      Distribution levels:
                                                          * 0: Your organisation only
                                                          * 1: This community only
                                                          * 2: Connected communities
                                                          * 3: All communities

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
        parser_create_event.add_argument("-d", "--distrib", required=True, type=int, choices=[0, 1, 2, 3], help="Distribution of the attributes for the new event.")
        parser_create_event.add_argument("-t", "--threat", required=True, type=int, choices=[0, 1, 2, 3], help="Threat level of a new event.")
        parser_create_event.add_argument("-a", "--analysis", required=True, type=int, choices=[0, 1, 2], help="Analysis level a new event.")
        parser_create_event.add_argument("-i", "--info", required=True, nargs='+', help="Event info field of a new event.")
        parser_create_event.add_argument("--date", help="Date of the event. (Default: today).")

        # ##### Add attributes #####
        parser_add = subparsers.add_parser('add', help='Add attributes to an existing MISP event.')
        subparsers_add = parser_add.add_subparsers(dest='add')
        # Hashes
        h = subparsers_add.add_parser("hashes", help="If no parameters, add all the hashes of the current session.")
        h.add_argument("-f", "--filename", help="Filename")
        h.add_argument("-m", "--md5", help="MD5")
        h.add_argument("-s", "--sha1", help="SHA1")
        h.add_argument("-a", "--sha256", help="SHA256")
        # Registry key
        rk = subparsers_add.add_parser("regkey", help="Add a registry key to the event.")
        rk.add_argument("regkey", nargs='+', help="First word is the key, second word (optional) is the value: <key> <value>")
        # Pipe
        pipe = subparsers_add.add_parser("pipe", help="Add a pipe to the event.")
        pipe.add_argument("pipe", help='Name of the pipe.')
        # Mutex
        mutex = subparsers_add.add_parser("mutex", help="Add a mutex to the event.")
        mutex.add_argument("mutex", help='Name of the mutex.')
        # IP Destination
        ipdst = subparsers_add.add_parser("ipdst", help="Add a destination IP (C&C Server) to the event.")
        ipdst.add_argument("ipdst", help='IP address')
        # Hostname
        hostname = subparsers_add.add_parser("hostname", help="Add an hostname to the event.")
        hostname.add_argument("hostname", help='Hostname')
        # Domain
        domain = subparsers_add.add_parser("domain", help="Add a domain to the event.")
        domain.add_argument("domain", help='Domain')
        # URL
        url = subparsers_add.add_parser("url", help="Add a URL to the event.")
        url.add_argument("full_url", help='URL')
        # User Agent
        ua = subparsers_add.add_parser("ua", help="Add a user-agent to the event.")
        ua.add_argument("ua", help='User Agent')
        # Pattern in file
        pfile = subparsers_add.add_parser("pattern_file", help="Add a pattern in file to the event.")
        pfile.add_argument("pfile", help='Pattern in file')
        # Pattern in Memory
        pmem = subparsers_add.add_parser("pattern_mem", help="Add a pattern in memory to the event.")
        pmem.add_argument("pmem", help='Pattern in memory')
        # Pattern in traffic
        ptraffic = subparsers_add.add_parser("pattern_traffic", help="Add a  to the event.")
        ptraffic.add_argument("ptraffic", help='Pattern in traffic')

        # ##### Show attributes  #####
        subparsers.add_parser('show', help='Show attributes to an existing MISP event.')

        # ##### Open file #####
        o = subparsers.add_parser('open', help='Open a sample from the temp directory.')
        ox = o.add_mutually_exclusive_group(required=True)
        ox.add_argument("-l", "--list", action='store_true', help="List available files")
        ox.add_argument("-d", "--delete", help="Delete temporary files (use 'all' to remove all the local samples or an Event ID to only remove the associated samples)")
        ox.add_argument("sid", nargs='?', type=int, help='Sample ID to open (from the list option).')

        # ##### Publish an event #####
        subparsers.add_parser('publish', help='Publish an existing MISP event.')

        # ##### Show version #####
        subparsers.add_parser('version', help='Returns the version of the MISP instance.')

        # Store
        s = subparsers.add_parser('store', help='Store the current MISP event in the current project.')
        s.add_argument("-l", "--list", action='store_true', help="List stored MISP events")
        s.add_argument("-u", "--update", action='store_true', help="Update all stored MISP events")
        s.add_argument("-d", "--delete", type=int, help="Delete a stored MISP event")
        s.add_argument("-o", "--open", type=int, help="Open a stored MISP event")

        self.categories = {0: 'Payload delivery', 1: 'Artifacts dropped', 2: 'Payload installation', 3: 'External analysis'}

    # ####### Generic Helpers ########
    def _get_eventid(self, quiet=False):
        if vars(self.args).get('event'):
            return self.args.event
        else:
            # Get current event ID if possible
            if not __sessions__.is_attached_misp(quiet):
                return None
            return __sessions__.current.misp_event.event_id

    def _has_error_message(self, result):
        if result.get('errors'):
            for message in result['errors']:
                self.log('error', message)
            return True
        return False

    def _search_local_hashes(self, event, open_session=True):
        local = []
        samples_count = 0
        if event.get('Event') is None:
            self.log('error', event)
            return
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
        self.log('info', 'Event {} contains {} samples.'.format(event['Event']['id'], samples_count))
        if not open_session:
            return
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

    # ####### Helpers for check_hashes ########

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
        comment = curattr['comment']
        if not link[0]:
            attibutes.append({'type': 'link', 'category': 'External analysis', 'comment': comment,
                              'to_ids': False, 'distribution': distrib, 'value': link[1]})
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
        result = self.misp.update(to_send)
        if not self._has_error_message(result):
            self.log('success', "All attributes updated sucessfully")
            __sessions__.new(misp_event=MispEvent(result))

    # ####### Helpers for add ########

    def _find_related_id(self, event):
        if not event.get('RelatedEvent'):
            return []
        related = []
        for events in event.get('RelatedEvent'):
            for info in events['Event']:
                related.append((int(info['id']), info['info'].encode('utf-8')))
        to_return = list(set(related))
        to_return.sort(key=lambda tup: tup[0])
        return to_return

    def _check_add(self, new_event):
        if not new_event.get('Event'):
            self.log('error', new_event)
            return
        old_related = self._find_related_id(__sessions__.current.misp_event.event.get('Event'))
        new_related = self._find_related_id(new_event.get('Event'))
        old_related_ids = [i[0] for i in old_related]
        for related, title in new_related:
            if related not in old_related_ids:
                self.log('success', u'New related event: {}/events/view/{} - {}'.format(self.url.rstrip('/'), related, title))
            else:
                self.log('info', 'Related event: {}/events/view/{} - {}'.format(self.url.rstrip('/'), related, title))
        __sessions__.new(misp_event=MispEvent(new_event))

    # ####### Helpers for open ########

    def _load_tmp_samples(self):
        tmp_samples = []
        samples_path = os.path.join(self.cur_path, 'misp_samples')
        path = os.path.join(samples_path, '*')
        for p in glob.glob(path):
            eid = os.path.basename(p)
            fullpath = os.path.join(samples_path, eid, '*')
            for p in glob.glob(fullpath):
                name = os.path.basename(p)
                tmp_samples.append((eid, p, name))
        return tmp_samples

    def _display_tmp_files(self):
        cureid = None
        if __sessions__.is_attached_misp(True):
            cureid = self._get_eventid()
        header = ['Sample ID', 'Current', 'Event ID', 'Filename']
        rows = []
        i = 0
        tmp_samples = self._load_tmp_samples()
        if len(tmp_samples) == 0:
            self.log('warning', 'No temporary samples available.')
            return
        for eid, path, name in tmp_samples:
            if eid == cureid:
                rows.append((i, '*', eid, name))
            else:
                rows.append((i, '', eid, name))
            i += 1
        self.log('table', dict(header=header, rows=rows))

    def _clean_tmp_samples(self, eid):
        samples_path = os.path.join(self.cur_path, 'misp_samples')
        to_remove = os.path.join(samples_path)
        if eid != 'all':
            to_remove = os.path.join(to_remove, eid)
        if os.path.exists(to_remove):
            shutil.rmtree(to_remove)
            return True
        return False

    # ##########################################

    def yara(self):
        ok = False
        data = None
        event_id = self._get_eventid()
        if event_id is None:
            return
        ok, data = self.misp.get_yara(event_id)
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
        if self.args.hash:
            ok, data = self.misp.download_samples(sample_hash=self.args.hash)
        elif self.args.list is not None:
            list_events = []
            if len(self.args.list) == 0:
                event_path = os.path.join(self.cur_path, 'misp_events')
                for eid, path, title in self._get_local_events(event_path):
                    list_events.append(eid)
            else:
                list_events = self.args.list

            all_data = []
            for eid in list_events:
                event = self.misp.get(eid)
                ok, data = self.misp.download_samples(event_id=event['Event']['id'])
                if not ok:
                    self.log('error', data)
                    continue
                if data:
                    all_data += data
            data = all_data
        else:
            event_id = self._get_eventid()
            if event_id is None:
                return
            ok, data = self.misp.download_samples(event_id=event_id)

            if not ok:
                self.log('error', data)
                return
        to_print = []
        samples_path = os.path.join(self.cur_path, 'misp_samples')
        for d in data:
            eid, filename, payload = d
            path = os.path.join(samples_path, eid, filename)
            if not os.path.exists(os.path.dirname(path)):
                os.makedirs(os.path.dirname(path))
            with open(path, 'w') as f:
                f.write(payload.getvalue())
            to_print.append((eid, path))

        if len(to_print) == 1:
            self.log('success', 'The sample has been downloaded from Event {}'.format(to_print[0][0]))
            event = self.misp.get(to_print[0][0])
            if not self._has_error_message(event):
                return __sessions__.new(to_print[0][1], MispEvent(event))
        elif len(to_print) > 1:
            self.log('success', 'The following files have been downloaded:')
            self._display_tmp_files()
        else:
            self.log('warning', 'No samples available.')

    def upload(self):
        categ = self.categories.get(self.args.categ)
        if self.args.info is not None:
            info = ' '.join(self.args.info)
        else:
            info = None
        if self.args.comment is not None:
            comment = ' '.join(self.args.comment)
        else:
            comment = None
        # No need to check the output: is the event_id is none, we create a new one.
        event_id = self._get_eventid(True)
        try:
            result = self.misp.upload_sample(__sessions__.current.file.name, __sessions__.current.file.path,
                                             event_id, self.args.distrib, self.args.ids, categ, info, comment,
                                             self.args.analysis, self.args.threat)
        except Exception as e:
            self.log('error', e)
            return
        if not self._has_error_message(result):
            self.log('success', "File uploaded sucessfully")
            if event_id is None:
                event_id = result['id']
            full_event = self.misp.get(event_id)
            if not self._has_error_message(full_event):
                return __sessions__.new(misp_event=MispEvent(full_event))

    def check_hashes(self):
        event_id = self._get_eventid()
        if event_id is None:
            return
        event = self.misp.get(event_id)
        if self._has_error_message(event):
            return

        e = event.get('Event')
        event_hashes = []
        sample_hashes = []
        base_new_attributes = {}
        for a in e['Attribute']:
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
        vt_request = {'apikey': cfg.virustotal.virustotal_key}
        # Make sure to start getting reports for the longest possible hashes (reduce risks of collisions)
        hashes_to_check = sorted(event_hashes, key=len)
        while len(hashes_to_check) > 0:
            vt_request['resource'] = hashes_to_check.pop()
            try:
                response = requests.post(cfg.misp.misp_vturl, data=vt_request)
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
                for a in e['Attribute']:
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
            self._populate(e, attributes)
        if len(unk_vt_hashes) > 0:
            self.log('error', 'Unknown on VT:')
            for h in unk_vt_hashes:
                self.log('item', '{}'.format(h))

    def searchall(self):
        if self.args.query:
            self._search(' '.join(self.args.query))
        else:
            if not __sessions__.is_attached_file(True):
                self.log('error', "Not attached to a file, nothing to serch for.")
                return False
            to_search = [__sessions__.current.file.md5, __sessions__.current.file.sha1, __sessions__.current.file.sha256]
            for q in to_search:
                self._search(q)

    def _search(self, query):
        result = self.misp.search_all(query)

        if self._has_error_message(result):
            return
        self.log('success', '{} matches on the following events:'.format(query))
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

    def pull(self):
        open_session = len(self.args.event) == 1
        for e in self.args.event:
            event = self.misp.get(e)
            if not self._has_error_message(event):
                self._search_local_hashes(event, open_session)
                self._dump(event)

    def create_event(self):
        # Dirty trick to keep consistency in the module: the threat level in the upload
        # API can go from 0 import to 3 but it is 1 to 4 in the event mgmt API.
        # It will be fixed in a near future, in the mean time, we do that:
        self.args.threat += 1

        if self.args.info is not None:
            info = ' '.join(self.args.info)
        else:
            info = None

        event = self.misp.new_event(self.args.distrib, self.args.threat, self.args.analysis, info, self.args.date)
        if self._has_error_message(event):
            return
        self._search_local_hashes(event)

    def publish(self):
        current_event = copy.deepcopy(__sessions__.current.misp_event.event)
        event = self.misp.publish(current_event)
        if not self._has_error_message(event):
            self.log('success', 'Event {} published.'.format(event['Event']['id']))
            __sessions__.new(misp_event=MispEvent(event))

    def open(self):
        if self.args.list:
            self._display_tmp_files()
        elif self.args.delete:
            if self.args.delete != 'all':
                try:
                    int(self.args.delete)
                except:
                    self.log('error', 'You can only delete all the samples of the samples of a specific event ID.')
                    return
            if self._clean_tmp_samples(self.args.delete):
                self.log('success', 'Sucessfully removed.')
            else:
                self.log('error', 'Nothing to remove.')
        else:
            tmp_samples = self._load_tmp_samples()
            try:
                eid, path, name = tmp_samples[int(self.args.sid)]
            except IndexError:
                self.log('error', 'Invalid sid, please use misp open -l.')
                return
            event = self.misp.get(eid)
            if not self._has_error_message(event):
                return __sessions__.new(path, MispEvent(event))

    def show(self):
        current_event = __sessions__.current.misp_event.event

        related = self._find_related_id(current_event.get('Event'))
        if len(related) > 0:
            self.log('info', 'Related events:')
            for r, title in related:
                self.log('item', '{}/events/view/{} - {}'.format(self.url.rstrip('/'), r, title))

        header = ['type', 'value', 'comment', 'related']
        rows = []
        for a in current_event['Event']['Attribute']:
            idlist = []
            if a.get('RelatedAttribute'):
                for r in a.get('RelatedAttribute'):
                    idlist.append(r['id'])
            rows.append([a['type'], a['value'], '\n'.join(textwrap.wrap(a['comment'], 30)), '\n'.join(textwrap.wrap(' '.join(idlist), 15))])
        self.log('table', dict(header=header, rows=rows))
        if current_event['Event']['published']:
            self.log('info', 'This event has been published')
        else:
            self.log('info', 'This event has not been published')
        self.log('info', 'Link to Event: {}/events/view/{}'.format(self.url.rstrip('/'), __sessions__.current.misp_event.event_id))

    def add(self):
        current_event = copy.deepcopy(__sessions__.current.misp_event.event)

        if self.args.add == 'hashes':
            if self.args.filename is None and self.args.md5 is None and self.args.sha1 is None and self.args.sha256 is None:
                if not __sessions__.is_attached_file(True):
                    self.log('error', "Not attached to a file, please set the hashes manually.")
                    return False
                event = self.misp.add_hashes(current_event, filename=__sessions__.current.file.name,
                                             md5=__sessions__.current.file.md5, sha1=__sessions__.current.file.sha1,
                                             sha256=__sessions__.current.file.sha256,
                                             comment=__sessions__.current.file.tags)
            else:
                event = self.misp.add_hashes(current_event, filename=self.args.filename,
                                             md5=self.args.md5, sha1=self.args.sha1, sha256=self.args.sha256)
        elif self.args.add == 'regkey':
            if len(self.args.regkey) == 2:
                reg, val = self.args.regkey
            else:
                reg = self.args.regkey[0]
                val = None
            event = self.misp.add_regkey(current_event, reg, val)
        elif self.args.add == 'pipe':
            event = self.misp.add_pipe(current_event, self.args.pipe)
        elif self.args.add == 'mutex':
            event = self.misp.add_mutex(current_event, self.args.mutex)
        elif self.args.add == 'ipdst':
            event = self.misp.add_ipdst(current_event, self.args.ipdst)
        elif self.args.add == 'hostname':
            event = self.misp.add_hostname(current_event, self.args.hostname)
        elif self.args.add == 'domain':
            event = self.misp.add_domain(current_event, self.args.domain)
        elif self.args.add == 'url':
            event = self.misp.add_url(current_event, self.args.full_url)
        elif self.args.add == 'ua':
            event = self.misp.add_useragent(current_event, self.args.ua)
        elif self.args.add == 'pattern_file':
            event = self.misp.add_pattern(current_event, self.args.pfile, True, False)
        elif self.args.add == 'pattern_mem':
            event = self.misp.add_pattern(current_event, self.args.pmem, False, True)
        elif self.args.add == 'pattern_traffic':
            event = self.misp.add_traffic_pattern(current_event, self.args.ptraffic)

        if self._has_error_message(event):
            return
        self._check_add(event)

    def version(self):
        api_ok = True

        api_version = self.misp.get_api_version()
        self.log('info', 'The version of your MISP API is: {}'.format(api_version['version']))
        api_version_master = self.misp.get_api_version_master()
        if self._has_error_message(api_version_master):
            api_ok = False
        else:
            self.log('info', 'The version of MISP API master branch is: {}'.format(api_version_master['version']))

        if api_ok:
            if api_version['version'] == api_version_master['version']:
                self.log('success', 'Congratulation, the MISP API installed is up-to-date')
            else:
                self.log('warning', 'The MISP API installed is outdated, you should update to avoid issues.')

        instance_ok = True

        misp_version = self.misp.get_version()
        if self._has_error_message(misp_version):
            instance_ok = False
        else:
            self.log('info', 'The version of your MISP instance is: {}'.format(misp_version['version']))

        misp_version_master = self.misp.get_version_master()
        if self._has_error_message(misp_version_master):
            instance_ok = False
        else:
            self.log('info', 'The version of MISP master branch is: {}'.format(misp_version_master['version']))

        if instance_ok:
            if misp_version['version'] == misp_version_master['version']:
                self.log('success', 'Congratulation, your MISP instance is up-to-date')
            else:
                master_major, master_minor, master_hotfix = misp_version_master['version'].split('.')
                major, minor, hotfix = misp_version['version'].split('.')
                if master_major < major or master_minor < minor or master_hotfix < hotfix:
                    self.log('warning', 'Your MISP instance is more recent than master, you must be using a beta version and probably know what you are doing. Enjoy!')
                else:
                    self.log('warning', 'Your MISP instance is outdated, you should update to avoid issues with the API.')

    def _get_local_events(self, path):
        tmp_local = []
        path = os.path.join(path, '*')
        for p in glob.glob(path):
            eid = os.path.basename(p).rstrip('.json')
            e_json = json.loads(open(p, 'r').read())
            tmp_local.append((eid, p, e_json['Event']['info']))
        return tmp_local

    def _dump(self, event):
        event_path = os.path.join(self.cur_path, 'misp_events')
        if not os.path.exists(event_path):
            os.makedirs(event_path)
        path = os.path.join(event_path, '{}.json'.format(event['Event']['id']))
        with open(path, 'w') as f:
            f.write(json.dumps(event))
        self.log('success', '{} stored successfully.'.format(event['Event']['id']))

    def store(self):
        try:
            event_path = os.path.join(self.cur_path, 'misp_events')
            if not os.path.exists(event_path):
                os.mkdir(event_path)
            if self.args.list:
                header = ['Event ID', 'Title']
                rows = []
                for eid, path, title in self._get_local_events(event_path):
                    rows.append((eid, title))
                self.log('table', dict(header=header, rows=sorted(rows, key=lambda i: (int(i[0])))))
            elif self.args.update:
                for eid, path, title in self._get_local_events(event_path):
                    event = self.misp.get(eid)
                    with open(path, 'w') as f:
                        f.write(json.dumps(event))
                    self.log('success', '{} updated successfully.'.format(eid))
            elif self.args.delete:
                path = os.path.join(event_path, '{}.json'.format(self.args.delete))
                if os.path.exists(path):
                    os.remove(path)
                    self.log('success', '{} removed successfully.'.format(self.args.delete))
                else:
                    self.log('error', '{} does not exists.'.format(self.args.delete))
            elif self.args.open:
                path = os.path.join(event_path, '{}.json'.format(self.args.open))
                if os.path.exists(path):
                    e_json = json.loads(open(path, 'r').read())
                    __sessions__.new(misp_event=MispEvent(e_json))
                else:
                    self.log('error', '{} does not exists.'.format(self.args.open))
            elif __sessions__.is_attached_misp():
                self._dump(__sessions__.current.misp_event.event)
        except IOError as e:
            self.log('error', e.strerror)

    def run(self):
        super(MISP, self).run()
        if self.args is None:
            return

        if not HAVE_PYMISP:
            self.log('error', "Missing dependency, install pymisp (`pip install pymisp`)")
            return

        if self.args.url is None:
            self.url = cfg.misp.misp_url
        else:
            self.url = self.args.url

        if self.args.key is None:
            self.key = cfg.misp.misp_key
        else:
            self.key = self.args.key

        if self.url is None:
            self.log('error', "This command requires the URL of the MISP instance you want to query.")
            return
        if self.key is None:
            self.log('error', "This command requires a MISP private API key.")
            return

        if not self.args.verify:
            verify = False
        else:
            verify = cfg.misp.misp_verify

        try:
            self.misp = PyMISP(self.url, self.key, verify, 'json')
        except PyMISPError as e:
            self.log('error', e.message)
            return

        # Require an open MISP session
        if self.args.subname in ['add', 'show', 'publish'] and not __sessions__.is_attached_misp():
            return

        # Require an open file session
        if self.args.subname in ['upload'] and not __sessions__.is_attached_file():
            return

        try:
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
            elif self.args.subname == 'pull':
                self.pull()
            elif self.args.subname == 'create_event':
                self.create_event()
            elif self.args.subname == 'add':
                self.add()
            elif self.args.subname == 'show':
                self.show()
            elif self.args.subname == 'open':
                self.open()
            elif self.args.subname == 'publish':
                self.publish()
            elif self.args.subname == 'version':
                self.version()
            elif self.args.subname == 'store':
                self.store()
            else:
                self.log('error', "No calls defined for this command.")
        except requests.exceptions.HTTPError as e:
            self.log('error', e)
