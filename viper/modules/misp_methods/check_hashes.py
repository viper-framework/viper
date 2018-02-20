# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import time
import datetime

try:
    from pymisp import MISPEvent, InvalidMISPObject, MISPObject
    from pymisp.tools import VTReportObject, make_binary_objects
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


def _populate(self, event):
    result = self.misp.update(event)

    if not self._has_error_message(result):
        self.log('success', "All attributes updated successfully")
        event_id = self._get_eventid()
        if event_id is None:
            return
        event = self.misp.get(event_id)
        if self._has_error_message(event):
            return
        __sessions__.new(misp_event=MispEvent(event, self.offline_mode))


def _expand_local_sample(self, pseudofile, filename, refobj=None, default_attributes_parameters={}):
    objs = []
    hashes = []
    # Just expand the event with every possible objects
    fo, peo, seos = make_binary_objects(pseudofile=pseudofile, filename=filename,
                                        standalone=False,
                                        default_attributes_parameters=default_attributes_parameters)
    fo.add_reference(refobj, 'derived-from')
    hashes += [h.value for h in fo.get_attributes_by_relation('sha256')]
    hashes += [h.value for h in fo.get_attributes_by_relation('sha1')]
    hashes += [h.value for h in fo.get_attributes_by_relation('md5')]
    if self.args.populate:
        objs.append(fo)
        if peo:
            objs.append(peo)
        if seos:
            objs += seos
    return objs, hashes


def _make_VT_object(self, to_search, default_attributes_parameters):
    try:
        vt_object = VTReportObject(cfg.virustotal.virustotal_key, to_search,
                                   vt_proxies=cfg.virustotal.proxies, standalone=False,
                                   default_attributes_parameters=default_attributes_parameters)
        if self.args.populate:
            vt_object.distribution = default_attributes_parameters.distribution
        return vt_object
    except requests.exceptions.ConnectionError:
        self.log('error', 'Failed to connect to VT for {}'.format(to_search))
        return
    except InvalidMISPObject as e:
        self.log('error', e)
    return None


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
    hashes_to_expand = {}
    hashes_expanded = []  # Thoses hashes are known and already processed
    local_samples_hashes = []
    partial_objects = {}
    for o in misp_event.Object:
        if o.name != 'file':
            continue
        if o.has_attributes_by_relation(['md5', 'sha1', 'sha256']):
            # This object has all the hashes we care about
            tmphashes = []
            tmphashes += [h.value for h in o.get_attributes_by_relation('md5')]
            tmphashes += [h.value for h in o.get_attributes_by_relation('sha1')]
            tmphashes += [h.value for h in o.get_attributes_by_relation('sha256')]
            # Make sure to query VT for the sha256, even if expanded locally
            hashes_to_expand[o.get_attributes_by_relation('sha256')[0].value] = o.get_attributes_by_relation('sha256')[0]
            if o.has_attributes_by_relation(['malware-sample']):
                # ... and it has a malware sample
                local_samples_hashes += tmphashes
            hashes_expanded += tmphashes
        elif o.has_attributes_by_relation(['malware-sample']):
            # This object has a malware sample, but is missing hashes. We can expand locally.
            # get the MD5 from the malware-sample attribute
            malware_sample = o.get_attributes_by_relation('malware-sample')[0]  # at most one sample/file object
            local_samples_hashes.append(malware_sample.value.split('|')[1])
            local_samples_hashes += [h.value for h in o.get_attributes_by_relation('md5')]
            local_samples_hashes += [h.value for h in o.get_attributes_by_relation('sha1')]
            local_samples_hashes += [h.value for h in o.get_attributes_by_relation('sha256')]
            if self.args.populate:
                # The object is missing hashes, keeping track of it for expansion if it isn't already done.
                partial_objects[o.uuid] = malware_sample

        else:
            sha256 = {attribute.value: attribute for attribute in o.get_attributes_by_relation('sha256')}
            sha1 = {attribute.value: attribute for attribute in o.get_attributes_by_relation('sha1')}
            md5 = {attribute.value: attribute for attribute in o.get_attributes_by_relation('md5')}
            if sha256:
                hashes_to_expand.update(sha256)
            elif sha1:
                hashes_to_expand.update(sha1)
            elif md5:
                hashes_to_expand.update(md5)

    for ref_uuid, sample in partial_objects.items():
        if sample.value.split('|')[1] in hashes_expanded:
            # Already expanded in an other object
            continue
        new_obj, hashes = self._expand_local_sample(pseudofile=sample.malware_binary,
                                                    filename=sample.value.split('|')[0],
                                                    refobj=ref_uuid,
                                                    default_attributes_parameters=sample)
        misp_event.Object += new_obj
        local_samples_hashes += hashes
        # Make sure to query VT for the sha256, even if expanded locally
        hashes_to_expand[hashes[0]] = sample

    hashes_expanded += local_samples_hashes
    for a in misp_event.attributes:
        if a.type == 'malware-sample' and a.value.split('|')[1] not in hashes_expanded:
            new_obj, hashes = self._expand_local_sample(pseudofile=a.malware_binary,
                                                        filename=a.value.split('|')[0],
                                                        default_attributes_parameters=a)
            misp_event.Object += new_obj
            local_samples_hashes += hashes
            # Make sure to query VT for the sha256, even if expanded locally
            hashes_to_expand[hashes[0]] = a
        elif a.type in ('filename|md5', 'filename|sha1', 'filename|sha256'):
            # We don't care if the hashes are in hashes_expanded or hashes_to_expand: they are firtered out later anyway
            fname, hashval = a.value.split('|')
            hashes_to_expand[hashval] = a
        elif a.type in ('md5', 'sha1', 'sha256'):
            # We don't care if the hashes are in hashes_expanded or hashes_to_expand: they are firtered out later anyway
            hashes_to_expand[a.value] = a

    unk_vt_hashes = []
    if cfg.virustotal.virustotal_has_private_key is False:
        quota = 4
        timeout = datetime.datetime.now() + datetime.timedelta(minutes=1)

    hashes_expanded += local_samples_hashes
    processed_on_vt = []
    # Make sure to start getting reports for the longest possible hashes (reduce risks of collisions)
    for to_expand in sorted(list(set(hashes_to_expand)), key=len):
        if to_expand in processed_on_vt:
            # Always run VT, once per sample
            continue
        original_attribute = hashes_to_expand[to_expand]
        if original_attribute.get('object_id'):
            original_object_id = original_attribute.get('object_id')
        vt_object = self._make_VT_object(to_expand, original_attribute)
        if not vt_object:
            unk_vt_hashes.append(to_expand)
            continue
        result = vt_object.get_report()
        md5 = result['md5']
        sha1 = result['sha1']
        sha256 = result['sha256']
        processed_on_vt += [sha256, sha1, md5]
        if all(h in local_samples_hashes for h in [md5, sha1, sha256]):
            self.log('success', 'Sample available in MISP:')
        else:
            self.log('success', 'Sample available in VT:')
        self.log('item', '{}\n\t{}\n\t{}\n\t{}'.format(result["permalink"], md5, sha1, sha256))
        if self.args.populate:
            if not all(h in hashes_expanded for h in [md5, sha1, sha256]):
                # If all the "new" expanded hashes are in the hashes_expanded list, skip
                file_object = MISPObject('file', default_attributes_parameters=original_attribute)
                file_object.add_attribute('md5', value=md5)
                file_object.add_attribute('sha1', value=sha1)
                file_object.add_attribute('sha256', value=sha256)
                file_object.add_reference(vt_object.uuid, 'analysed-with')
                misp_event.Object.append(file_object)
                hashes_expanded += [md5, sha1, sha256]
            else:
                if not original_object_id or original_object_id == '0':
                    # Not an object, but the hashes are in an other object, skipping
                    continue
                else:
                    # We already have a MISP object, adding the link to the new VT object
                    file_object = misp_event.get_object_by_id(original_object_id)
                    file_object.add_reference(vt_object.uuid, 'analysed-with')
            misp_event.Object.append(vt_object)

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
        self._populate(misp_event)
    if len(unk_vt_hashes) > 0:
        self.log('error', 'Unknown on VT:')
        for h in unk_vt_hashes:
            self.log('item', '{}'.format(h))
