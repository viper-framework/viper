# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import time
import datetime

try:
    from pymisp import MISPEvent, InvalidMISPObject, MISPObject
    from pymisp.tools import VTReportObject
    HAVE_PYMISP = True
except ImportError:
    HAVE_PYMISP = False

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False


from viper.core.session import __sessions__
from viper.common.objects import MispEvent
from viper.core.config import __config__

cfg = __config__


# ####### Helpers for check_hashes ########

def _prepare_attributes(self, md5, sha1, sha256, vt_object, base_attr):

    # Figuring out which hash was in MISP and has the rest of the parameters
    curattr = None
    if base_attr.get(sha256):
        curattr = base_attr.get(sha256)
    elif base_attr.get(sha1):
        curattr = base_attr.get(sha1)
    else:
        curattr = base_attr.get(md5)

    file_object = MISPObject('file')
    file_object.add_attribute('md5', value=md5, **curattr)
    file_object.add_attribute('sha1', value=sha1, **curattr)
    file_object.add_attribute('sha256', value=sha256, **curattr)
    file_object.add_reference(vt_object.uuid, 'analysed-with')

    return file_object


def _populate(self, event, vt_object, file_object):
    # Get template ID of VT object
    vt_template_id = self.misp.get_object_template_id(vt_object.template_uuid)
    # Get template ID of file object
    file_template_id = self.misp.get_object_template_id(file_object.template_uuid)

    # Add VT object:
    result = self.misp.add_object(event.id, vt_template_id, vt_object)
    if self._has_error_message(result):
        self.log('error', 'foo')
        self.log('error', vt_object.to_json())
        return

    # Add File object
    result = self.misp.add_object(event.id, file_template_id, file_object)
    if self._has_error_message(result):
        self.log('error', 'bar')
        self.log('error', file_object.to_json())
        return
    result = self.misp.add_object_reference(file_object.ObjectReference[0])

    if not self._has_error_message(result):
        self.log('success', "All attributes updated successfully")
        event_id = self._get_eventid()
        if event_id is None:
            return
        event = self.misp.get(event_id)
        if self._has_error_message(event):
            return
        __sessions__.new(misp_event=MispEvent(event, self.offline_mode))


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
            if a.type == 'malware-sample':
                sample_hashes.append(h)

        if h is not None:
            base_new_attributes[h] = {"category": a.category,
                                      "to_ids": a.to_ids,
                                      "Tag": a.Tag,
                                      "distribution": a.distribution}

    unk_vt_hashes = []
    # Make sure to start getting reports for the longest possible hashes (reduce risks of collisions)
    hashes_to_check = sorted(event_hashes, key=len)
    if cfg.virustotal.virustotal_has_private_key is False:
        quota = 4
        timeout = datetime.datetime.now() + datetime.timedelta(minutes=1)

    while len(hashes_to_check) > 0:
        resource = hashes_to_check.pop()
        try:
            vt_object = VTReportObject(cfg.virustotal.virustotal_key, resource, vt_proxies=cfg.virustotal.proxies)
        except requests.exceptions.ConnectionError:
            self.log('error', 'Failed to connect to VT for {}'.format(resource))
            return
        except InvalidMISPObject as e:
            self.log('error', e)
            unk_vt_hashes.append(resource)
            continue
        result = vt_object.get_report()
        md5 = result['md5']
        sha1 = result['sha1']
        sha256 = result['sha256']
        hashes_to_check = [eh for eh in hashes_to_check if eh not in (md5, sha1, sha256)]
        if md5 in sample_hashes:
            self.log('success', 'Sample available in MISP:')
        else:
            self.log('success', 'Sample available in VT:')
        if self.args.populate:
            file_object = self._prepare_attributes(md5, sha1, sha256, vt_object, base_new_attributes)
        self.log('item', '{}\n\t{}\n\t{}\n\t{}'.format(result["permalink"], md5, sha1, sha256))
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

    if self.args.populate:
        self._populate(misp_event, vt_object, file_object)
    if len(unk_vt_hashes) > 0:
        self.log('error', 'Unknown on VT:')
        for h in unk_vt_hashes:
            self.log('item', '{}'.format(h))
