# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import glob
import json

try:
    from pymisp import MISPEvent, EncodeUpdate
    HAVE_PYMISP = True
except:
    HAVE_PYMISP = False

from viper.core.session import __sessions__
from viper.common.objects import MispEvent


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
