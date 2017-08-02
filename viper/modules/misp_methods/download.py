# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os

try:
    from pymisp import MISPEvent
    HAVE_PYMISP = True
except:
    HAVE_PYMISP = False

from viper.core.session import __sessions__
from viper.common.objects import MispEvent


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
