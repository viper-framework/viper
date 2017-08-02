# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import time
import datetime

try:
    from pymisp import MISPEvent
    HAVE_PYMISP = True
except:
    HAVE_PYMISP = False

try:
    import requests
    HAVE_REQUESTS = True
except:
    HAVE_REQUESTS = False


from viper.core.session import __sessions__
from viper.common.objects import MispEvent
from viper.core.config import Config

cfg = Config()


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
        self.log('success', "All attributes updated successfully")
        __sessions__.new(misp_event=MispEvent(result, self.offline_mode))


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
                                      "comment": '{} - Xchecked via VT: {}'.format(a.comment, h),
                                      "to_ids": a.to_ids,
                                      "Tag": a.Tag,
                                      "distribution": a.distribution}

    unk_vt_hashes = []
    vt_request = {'apikey': cfg.virustotal.virustotal_key}
    # Make sure to start getting reports for the longest possible hashes (reduce risks of collisions)
    hashes_to_check = sorted(event_hashes, key=len)
    original_attributes = len(misp_event.attributes)
    if cfg.virustotal.virustotal_has_private_key is False:
        quota = 4
        timeout = datetime.datetime.now() + datetime.timedelta(minutes=1)

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
            if cfg.virustotal.virustotal_has_private_key is False:
                if quota > 0:
                    quota -= 1
                else:
                    waiting_time = (timeout - datetime.datetime.now()).seconds
                    if waiting_time > 0:
                        self.log('warning', 'No private API key, 4 queries/min is the limit. Waiting for {} seconds.'.format(waiting_time))
                        time.sleep(waiting_time)
                    quota = 4
                    timeout = datetime.datetime.now() + datetime.timedelta(minutes=1)
        else:
            unk_vt_hashes.append(vt_request['resource'])

    if self.args.populate:
        self.__populate(misp_event, original_attributes)
    if len(unk_vt_hashes) > 0:
        self.log('error', 'Unknown on VT:')
        for h in unk_vt_hashes:
            self.log('item', '{}'.format(h))
