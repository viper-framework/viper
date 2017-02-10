# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import argparse
import textwrap
import os
import time
import glob
import shutil
import json

try:
    from pymisp import PyMISP, PyMISPError, MISPEvent, EncodeFull, EncodeUpdate
    HAVE_PYMISP = True
except:
    HAVE_PYMISP = False

try:
    from pytaxonomies import Taxonomies
    HAVE_PYTAX = True
except:
    HAVE_PYTAX = True


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
        self.parser.add_argument("--off", action='store_true', help='Use offline (can only work on pre-downloaded events)')
        self.parser.add_argument("--on", action='store_true', help='Switch to online mode')
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
        parser_create_event.add_argument("-d", "--distrib", type=int, choices=[0, 1, 2, 3], help="Distribution of the attributes for the new event.")
        parser_create_event.add_argument("-t", "--threat", type=int, choices=[0, 1, 2, 3], help="Threat level of a new event.")
        parser_create_event.add_argument("-a", "--analysis", type=int, choices=[0, 1, 2], help="Analysis level a new event.")
        parser_create_event.add_argument("-i", "--info", required=True, nargs='+', help="Event info field of a new event.")
        parser_create_event.add_argument("--date", help="Date of the event. (Default: today).")

        # ##### Add Hashes #####
        h = subparsers.add_parser("add_hashes", help="If no parameters, add all the hashes of the current session.")
        h.add_argument("-f", "--filename", help="Filename")
        h.add_argument("-m", "--md5", help="MD5")
        h.add_argument("-s", "--sha1", help="SHA1")
        h.add_argument("-a", "--sha256", help="SHA256")

        # ##### Add attributes #####
        parser_add = subparsers.add_parser('add', help='Add attributes to an existing MISP event.')
        subparsers_add = parser_add.add_subparsers(dest='add')
        # Hashes
        # Generic add
        temp_me = MISPEvent()
        for t in sorted(temp_me.types):
            sp = subparsers_add.add_parser(t, help="Add {} to the event.".format(t))
            sp.add_argument(t, nargs='+')

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
        s.add_argument("-s", "--sync", action='store_true', help="Sync all MISP Events with the remote MISP instance")
        s.add_argument("-d", "--delete", type=int, help="Delete a stored MISP event")
        s.add_argument("-o", "--open", help="Open a stored MISP event")

        # Tags
        s = subparsers.add_parser('tag', help='Tag managment using MISP taxonomies.')
        s.add_argument("-l", "--list", action='store_true', help="List Existing taxonomies.")
        s.add_argument("-d", "--details", help="Display all values of a taxonomy.")
        s.add_argument("-s", "--search", help="Search all tags matching a value.")
        s.add_argument("-e", "--event", help="Add tag to the current event.")
        s.add_argument("-a", "--attribute", nargs='+', help="Add tag to an attribute of the current event. Syntax: <identifier for the attribute> <machinetag>")

        self.categories = {0: 'Payload delivery', 1: 'Artifacts dropped', 2: 'Payload installation', 3: 'External analysis'}

    # ####### Generic Helpers ########
    def _get_eventid(self, quiet=False):
        if vars(self.args).get('event'):
            return self.args.event
        else:
            # Get current event ID if possible
            if not __sessions__.is_attached_misp(quiet):
                return None
            return __sessions__.current.misp_event.event.id

    def _has_error_message(self, result):
        if result.get('errors'):
            for message in result['errors']:
                self.log('error', message)
            return True
        elif result.get('error'):
            self.log('error', result.get('error'))
            return True
        return False

    def _search_local_hashes(self, event, open_session=True):
        local = []
        samples_count = 0
        if isinstance(event, MISPEvent):
            misp_event = event
        elif event.get('Event') is None:
            self.log('error', event)
            return
        else:
            misp_event = MISPEvent()
            misp_event.load(event)
        for a in misp_event.attributes:
            row = None
            if a.type == 'malware-sample':
                samples_count += 1
            if a.type in ('md5', 'sha1', 'sha256'):
                row = Database().find(key=a.type, value=a.value)
            elif a.type in ('filename|md5', 'filename|sha1', 'filename|sha256'):
                row = Database().find(key=a.type.split('|')[1], value=a.value.split('|')[1])
            elif a.type == 'malware-sample':
                row = Database().find(key='md5', value=a.value.split('|')[1])
            if row:
                local.append(row[0])
        self.log('info', 'Event {} contains {} samples.'.format(misp_event.id, samples_count))
        if not open_session:
            return
        shas = set([l.sha256 for l in local])
        if len(shas) == 1:
            __sessions__.new(get_sample_path(shas.pop()), MispEvent(misp_event, self.offline_mode))
        elif len(shas) > 1:
            self.log('success', 'The following samples are in this viper instance:')
            __sessions__.new(misp_event=MispEvent(misp_event, self.offline_mode))
            for s in shas:
                self.log('item', s)
        else:
            __sessions__.new(misp_event=MispEvent(misp_event, self.offline_mode))
            self.log('info', 'No known (in Viper) samples in that event.')

    # ####### Helpers for check_hashes ########

    def _prepare_attributes(self, md5, sha1, sha256, link, base_attr, event_hashes, sample_hashes, misp_event):
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

        if new_sha256:
            misp_event.add_attribute('sha256', sha256, **curattr)
        if new_sha1:
            misp_event.add_attribute('sha1', sha1, **curattr)
        if new_md5:
            misp_event.add_attribute('md5', md5, **curattr)

        if not link[0]:
            curattr['to_ids'] = False
            curattr['category'] = 'External analysis'
            misp_event.add_attribute('link', link[1], **curattr)
        return misp_event

    def _populate(self, event, original_attributes):
        if len(event.attributes) == original_attributes:
            self.log('info', "No new attributes to add.")
            return
        event.timestamp = int(time.time())
        result = self.misp.update(event._json())
        if not self._has_error_message(result):
            self.log('success', "All attributes updated sucessfully")
            __sessions__.new(misp_event=MispEvent(result, self.offline_mode))

    # ####### Helpers for add ########

    def _find_related_id(self, event):
        if not event.RelatedEvent:
            return []
        related = [(event.id, event.info) for event in event.RelatedEvent]
        to_return = list(set(related))
        to_return.sort(key=lambda tup: tup[0])
        return to_return

    def _check_add(self, new_event):
        old_related = self._find_related_id(__sessions__.current.misp_event.event)
        new_related = self._find_related_id(new_event)
        old_related_ids = [i[0] for i in old_related]
        for related, title in new_related:
            if related not in old_related_ids:
                self.log('success', u'New related event: {}/events/view/{} - {}'.format(self.url.rstrip('/'), related, title))
            else:
                self.log('info', u'Related event: {}/events/view/{} - {}'.format(self.url.rstrip('/'), related, title))
        __sessions__.new(misp_event=MispEvent(new_event, self.offline_mode))

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
        if self.offline_mode:
            self.log('error', 'Offline mode, unable to get yara rules')
            return
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
        if self.offline_mode:
            self.log('error', 'Offline mode, unable to dodnload a sample')
            return
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
                me = MISPEvent()
                me.load(self.misp.get(eid))
                ok, data = self.misp.download_samples(event_id=me.id)
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
                return __sessions__.new(to_print[0][1], MispEvent(event, self.offline_mode))
        elif len(to_print) > 1:
            self.log('success', 'The following files have been downloaded:')
            self._display_tmp_files()
        else:
            self.log('warning', 'No samples available.')

    def upload(self):
        if self.offline_mode:
            self.log('error', 'Offline mode, unable to upload a sample')
            return
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
                return __sessions__.new(misp_event=MispEvent(full_event, self.offline_mode))

    def check_hashes(self):
        if self.offline_mode:
            self.log('error', 'Offline mode, unable to query VirusTotal')
            return
        event_id = self._get_eventid()
        if event_id is None:
            return
        event = self.misp.get(event_id)
        if self._has_error_message(event):
            return

        misp_event = MISPEvent()
        misp_event.load(event)
        event_hashes = []
        sample_hashes = []
        base_new_attributes = {}
        for a in misp_event.attributes:
            h = None
            if a.type in ('md5', 'sha1', 'sha256'):
                h = a.value
                event_hashes.append(h)
            elif a.type in ('filename|md5', 'filename|sha1', 'filename|sha256', 'malware-sample'):
                h = a.value.split('|')[1]
                event_hashes.append(h)
            if h is not None:
                base_new_attributes[h] = {"category": a.category,
                                          "comment": u'{} - Xchecked via VT: {}'.format(a.comment, h),
                                          "to_ids": a.to_ids,
                                          "Tag": a.Tag,
                                          "distribution": a.distribution}

        unk_vt_hashes = []
        vt_request = {'apikey': cfg.virustotal.virustotal_key}
        # Make sure to start getting reports for the longest possible hashes (reduce risks of collisions)
        hashes_to_check = sorted(event_hashes, key=len)
        original_attributes = len(misp_event.attributes)
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
                for a in misp_event.attributes:
                    if a.value == link[1]:
                        link[0] = True
                if md5 in sample_hashes:
                    self.log('success', 'Sample available in MISP:')
                else:
                    self.log('success', 'Sample available in VT:')
                if self.args.populate:
                    misp_event = self._prepare_attributes(md5, sha1, sha256, link, base_new_attributes, event_hashes, sample_hashes, misp_event)
                self.log('item', '{}\n\t{}\n\t{}\n\t{}'.format(link[1], md5, sha1, sha256))
            else:
                unk_vt_hashes.append(vt_request['resource'])

        if self.args.populate:
            self._populate(misp_event, original_attributes)
        if len(unk_vt_hashes) > 0:
            self.log('error', 'Unknown on VT:')
            for h in unk_vt_hashes:
                self.log('item', '{}'.format(h))

    def searchall(self):
        if self.args.query:
            self._search(' '.join(self.args.query))
        else:
            if not __sessions__.is_attached_file(True):
                self.log('error', "Not attached to a file, nothing to search for.")
                return False
            to_search = [__sessions__.current.file.md5, __sessions__.current.file.sha1, __sessions__.current.file.sha256]
            for q in to_search:
                self._search(q)

    def _search(self, query):
        if self.offline_mode:
            self.log('error', 'Offline mode, unable to search')
            return
        result = self.misp.search_all(query)

        if self._has_error_message(result):
            return
        self.log('success', u'{} matches on the following events:'.format(query))
        for e in result['response']:
            nb_samples = 0
            nb_hashes = 0
            me = MISPEvent()
            me.load(e)
            for a in me.attributes:
                if a.type == 'malware-sample':
                    nb_samples += 1
                if a.type in ('md5', 'sha1', 'sha256', 'filename|md5', 'filename|sha1', 'filename|sha256'):
                    nb_hashes += 1
            self.log('item', u'{} ({} samples, {} hashes) - {}{}{}'.format(me.info, nb_samples, nb_hashes, self.url, '/events/view/', me.id))

    def pull(self):
        if self.offline_mode:
            self.log('error', 'Offline mode, unable to pull a remote event')
            return
        open_session = len(self.args.event) == 1
        for e in self.args.event:
            event = self.misp.get(e)
            if not self._has_error_message(event):
                self._search_local_hashes(event, open_session)
                self._dump(event)

    def create_event(self):
        if self.args.threat is not None:
            # Dirty trick to keep consistency in the module: the threat level in the upload
            # API can go from 0 import to 3 but it is 1 to 4 in the event mgmt API.
            # It will be fixed in a near future, in the meantime, we do that:
            self.args.threat += 1

        if not self.args.info:
            self.log('error', 'Info field is required for a new event')
        info = ' '.join(self.args.info)

        misp_event = MISPEvent()
        misp_event.set_all_values(info=info, distribution=self.args.distrib,
                                  threat_level_id=self.args.threat, analysis=self.args.analysis,
                                  date=self.args.date)
        self._search_local_hashes(misp_event)
        if self.offline_mode:
            # New event created locally, no ID
            __sessions__.current.misp_event.current_dump_file = self._dump()
            __sessions__.current.misp_event.offline()
        else:
            misp_event = self.misp.add_event(json.dumps(misp_event, cls=EncodeUpdate))
            if self._has_error_message(misp_event):
                return
            __sessions__.new(misp_event=MispEvent(misp_event, self.offline_mode))
            self._dump()

    def publish(self):
        __sessions__.current.misp_event.event.publish()
        if self.offline_mode:
            self._dump()
        else:
            event = self.misp.update(__sessions__.current.misp_event.event._json())
            if not self._has_error_message(event):
                self.log('success', 'Event {} published.'.format(event['Event']['id']))
                __sessions__.new(misp_event=MispEvent(event, self.offline_mode))

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
                return __sessions__.new(path, MispEvent(event, self.offline_mode))

    def show(self):
        current_event = __sessions__.current.misp_event.event

        related = self._find_related_id(current_event)
        if len(related) > 0:
            self.log('info', 'Related events:')
            for r, title in related:
                self.log('item', u'{}/events/view/{} - {}'.format(self.url.rstrip('/'), r, title))

        header = ['type', 'value', 'comment', 'related']
        rows = []
        for a in current_event.attributes:
            # FIXME: this has been removed upstream: https://github.com/MISP/MISP/issues/1793
            # Keeping it like that for now, until we decide how to re-enable it
            idlist = []
            if a.RelatedAttribute:
                for r in a.RelatedAttribute:
                    # idlist.append(r.id)
                    pass
            rows.append([a.type, a.value, '\n'.join(textwrap.wrap(a.comment, 30)), '\n'.join(textwrap.wrap(' '.join(idlist), 15))])
        self.log('table', dict(header=header, rows=rows))
        if current_event.published:
            self.log('info', 'This event has been published')
        else:
            self.log('info', 'This event has not been published')
        if __sessions__.current.misp_event.event.id:
            self.log('info', u'Link to Event: {}/events/view/{}'.format(self.url.rstrip('/'), __sessions__.current.misp_event.event.id))

    def _change_event(self):
        if self.offline_mode:
            self._dump()
        else:
            if __sessions__.current.misp_event.event.id:
                event = self.misp.update(__sessions__.current.misp_event.event._json())
            else:
                event = self.misp.add_event(json.dumps(__sessions__.current.misp_event.event, cls=EncodeUpdate))
            if self._has_error_message(event):
                return
            try:
                me = MISPEvent()
                me.load(event)
                self._check_add(me)
            except Exception as e:
                self.log('error', e)

    def add_hashes(self):
        if self.args.filename is None and self.args.md5 is None and self.args.sha1 is None and self.args.sha256 is None:
            if not __sessions__.is_attached_file(True):
                self.log('error', "Not attached to a file, please set the hashes manually.")
                return False
            __sessions__.current.misp_event.event.add_attribute('filename|md5', '{}|{}'.format(
                __sessions__.current.file.name, __sessions__.current.file.md5), comment=__sessions__.current.file.tags)
            __sessions__.current.misp_event.event.add_attribute('filename|sha1', '{}|{}'.format(
                __sessions__.current.file.name, __sessions__.current.file.sha1), comment=__sessions__.current.file.tags)
            __sessions__.current.misp_event.event.add_attribute('filename|sha256', '{}|{}'.format(
                __sessions__.current.file.name, __sessions__.current.file.sha256), comment=__sessions__.current.file.tags)
        else:
            if self.args.filename:
                if self.args.md5:
                    __sessions__.current.misp_event.event.add_attribute('filename|md5', '{}|{}'.format(
                        self.args.filename, self.args.md5))
                if self.args.sha1:
                    __sessions__.current.misp_event.event.add_attribute('filename|sha1', '{}|{}'.format(
                        self.args.filename, self.args.sha1))
                if self.args.sha256:
                    __sessions__.current.misp_event.event.add_attribute('filename|sha256', '{}|{}'.format(
                        self.args._filename, self.args.sha256))
            else:
                if self.args.md5:
                    __sessions__.current.misp_event.event.add_attribute('md5', self.args.md5)
                if self.args.sha1:
                    __sessions__.current.misp_event.event.add_attribute('sha1', self.args.sha1)
                if self.args.sha256:
                    __sessions__.current.misp_event.event.add_attribute('sha256', self.args.sha256)
        self._change_event()

    def add(self):
        __sessions__.current.misp_event.event.add_attribute(self.args.add, ' '.join(vars(self.args).get(self.args.add)))
        self._change_event()

    def version(self):
        if self.offline_mode:
            self.log('error', 'Offline mode, unable to check versions')
            return
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

        pymisp_recommended = self.misp.get_recommended_api_version()
        if self._has_error_message(pymisp_recommended):
            self.log('warning', "The MISP instance you're using doesn't have a recomended PyMISP version, update recommended.")
        else:
            self.log('info', 'The recommended version of PyMISP: {}'.format(pymisp_recommended['version']))
            for a, b in zip(pymisp_recommended['version'].split('.'), api_version['version'].split('.')):
                if a != b:
                    self.log('warning', "You're not using the recommended PyMISP version for this instance.")
                    break

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
            try:
                with open(p, 'r') as f:
                    e_json = json.load(f)
                tmp_local.append((eid, p, e_json['Event']['info']))
            except Exception as e:
                self.log('error', 'Unable to open {}: {}'.format(p, e))
        return tmp_local

    def _dump(self, event=None):
        event_path = os.path.join(self.cur_path, 'misp_events')
        if not os.path.exists(event_path):
            os.makedirs(event_path)

        if not event:
            to_dump = __sessions__.current.misp_event.event
        elif isinstance(event, MISPEvent):
            to_dump = event
        else:
            to_dump = MISPEvent()
            to_dump.load(event)
        if to_dump.id:
            filename = str(to_dump.id)
        elif (__sessions__.is_attached_misp(True) and
                __sessions__.current.misp_event.current_dump_file):
            filename = __sessions__.current.misp_event.current_dump_file
        else:
            i = 1
            while True:
                filename = 'new_event_{}.json'.format(i)
                if not os.path.exists(os.path.join(event_path, filename)):
                    break
                i += 1

        path = os.path.join(event_path, filename)
        with open(path, 'w') as f:
            json.dump(to_dump, f, cls=EncodeFull)
        self.log('success', '{} stored successfully.'.format(filename.rstrip('.json')))
        return filename

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
                self.log('table', dict(header=header, rows=sorted(rows, key=lambda i: (int(i[0].split('_')[-1])))))
            elif self.args.update:
                if self.offline_mode:
                    self.log('error', 'Offline mode, cannot update locally stored events.')
                    return
                for eid, path, title in self._get_local_events(event_path):
                    event = self.misp.get(eid)
                    with open(path, 'w') as f:
                        f.write(json.dumps(event))
                    self.log('success', '{} updated successfully.'.format(eid))
            elif self.args.sync:
                if self.offline_mode:
                    self.log('error', 'Offline mode, cannot synchronize locally stored events.')
                    return
                for eid, path, title in self._get_local_events(event_path):
                    __sessions__.close()
                    event = MISPEvent()
                    event.load(path)
                    if 'new_event_' in path:
                        event = self.misp.add_event(json.dumps(event, cls=EncodeUpdate))
                        try:
                            self._dump(event)
                            os.remove(path)
                        except Exception as e:
                            self.log('error', 'Unable to create new event: {}.'.format(e))
                    else:
                        eid = event.id
                        try:
                            event = self.misp.update(event._json())
                        except Exception as e:
                            self.log('error', 'Unable to update event {}: {}.'.format(eid, e))

                    if self._has_error_message(event):
                        return
            elif self.args.delete:
                path = os.path.join(event_path, '{}.json'.format(self.args.delete))
                if os.path.exists(path):
                    os.remove(path)
                    self.log('success', '{} removed successfully.'.format(self.args.delete))
                else:
                    self.log('error', '{} does not exists.'.format(self.args.delete))
            elif self.args.open:
                filename = '{}.json'.format(self.args.open)
                path = os.path.join(event_path, filename)
                if os.path.exists(path):
                    try:
                        with open(path, 'r') as f:
                            e_json = json.load(f)
                        __sessions__.new(misp_event=MispEvent(e_json, self.offline_mode))
                        __sessions__.current.misp_event.current_dump_file = filename
                    except Exception as e:
                        self.log('error', 'Unable to open {}: {}'.format(path, e))
                else:
                    self.log('error', '{} does not exists.'.format(self.args.open))
            elif __sessions__.is_attached_misp():
                self._dump()
        except IOError as e:
            self.log('error', e.strerror)

    def tag(self):
        if not HAVE_PYTAX:
            self.log('error', "Missing dependency, install PyTaxonomies (`pip install git+https://github.com/MISP/PyTaxonomies.git`)")
            return

        try:
            taxonomies = Taxonomies(manifest_path=os.path.join(self.local_dir_taxonomies, 'MANIFEST.json'))
        except Exception as e:
            self.log('error', 'Unable to open the taxonomies, please fix the config file ([misp] - misp_taxonomies_directory): {}'.format(e))
            return

        if self.args.list:
            self.log('table', dict(header=['Name', 'Description'], rows=[(title, tax.description)
                                                                         for title, tax in taxonomies.items()]))
        elif self.args.search:
            matches = taxonomies.search(self.args.search)
            if not matches:
                self.log('error', 'No tags matching "{}".'.format(self.args.search))
                return
            self.log('success', 'Tags matching "{}":'.format(self.args.search))
            for t in taxonomies.search(self.args.search):
                self.log('item', t)
        elif self.args.details:
            taxonomy = taxonomies.get(self.args.details)
            if not taxonomy:
                self.log('error', 'No taxonomy called "{}".'.format(self.args.details))
                return
            if taxonomy.description:
                self.log('info', taxonomy.description)
            elif taxonomy.expanded:
                self.log('info', taxonomy.expanded)
            if taxonomy.refs:
                self.log('info', 'References:')
                for r in taxonomy.refs:
                    self.log('item', r)
            if not taxonomy.has_entries():
                header = ['Description', 'Predicate', 'Machinetag']
                rows = []
                for p in taxonomy.predicates.values():
                    rows.append([p.description, p.predicate, taxonomy.make_machinetag(p)])
                self.log('table', dict(header=header, rows=rows))
            else:
                for p in taxonomy.predicates.values():
                    if p.description:
                        self.log('info', p.description)
                    elif p.expanded:
                        self.log('info', p.expanded)
                    else:
                        self.log('info', p.predicate)

                    if not p.entries:
                        self.log('item', taxonomy.make_machinetag(p))
                    else:
                        header = ['Description', 'Predicate', 'Machinetag']
                        rows = []
                        for e in p.entries.values():
                            if e.description:
                                descr = e.description
                            else:
                                descr = e.expanded
                            rows.append([descr, e.value, taxonomy.make_machinetag(p, e)])
                        self.log('table', dict(header=header, rows=rows))
        elif self.args.event:
            if not __sessions__.is_attached_misp():
                return
            try:
                taxonomies.revert_machinetag(self.args.event)
            except:
                self.log('error', 'Not a valid machine tag available in misp-taxonomies: "{}".'.format(self.args.event))
                return
            __sessions__.current.misp_event.event.add_tag(self.args.event)
            self._change_event()
        elif self.args.attribute:
            if not __sessions__.is_attached_misp():
                return
            identifier, tag = self.args.attribute
            try:
                taxonomies.revert_machinetag(tag)
            except:
                self.log('error', 'Not a valid machine tag available in misp-taxonomies: "{}".'.format(tag))
                return
            __sessions__.current.misp_event.event.add_attribute_tag(tag, identifier)
            self._change_event()

    def run(self):
        super(MISP, self).run()
        if self.args is None:
            return

        if not HAVE_PYMISP:
            self.log('error', "Missing dependency, install pymisp (`pip install pymisp`)")
            return

        self.offline_mode = False
        if self.args.on:
            self.offline_mode = False
            if __sessions__.is_attached_misp(True):
                __sessions__.current.misp_event.off = False
        elif self.args.off or (__sessions__.is_attached_misp(True) and
                               __sessions__.current.misp_event.off):
            self.offline_mode = True
            if __sessions__.is_attached_misp(True):
                __sessions__.current.misp_event.off = True

        self.url = self.args.url
        if self.url is None:
            self.url = cfg.misp.misp_url
        if self.url is None:
            self.log('error', "This command requires the URL of the MISP instance you want to query.")
            return

        self.key = self.args.key
        if self.key is None:
            self.key = cfg.misp.misp_key
        if self.key is None:
            self.log('error', "This command requires a MISP private API key.")
            return

        if not self.args.verify:
            verify = False
        else:
            verify = cfg.misp.misp_verify

        if cfg.misp.misp_taxonomies_directory:
            self.local_dir_taxonomies = cfg.misp.misp_taxonomies_directory

        if not self.offline_mode:
            try:
                self.misp = PyMISP(self.url, self.key, verify, 'json')
            except PyMISPError as e:
                self.log('error', e.message)
                return

        # Require an open MISP session
        if self.args.subname in ['add_hashes', 'add', 'show', 'publish'] and not __sessions__.is_attached_misp():
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
            elif self.args.subname == 'add_hashes':
                self.add_hashes()
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
            elif self.args.subname == 'tag':
                self.tag()
            else:
                self.log('error', "No calls defined for this command.")
        except requests.exceptions.HTTPError as e:
            self.log('error', e)
