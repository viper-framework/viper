# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import glob
import shutil

from viper.core.session import __sessions__
from viper.common.objects import MispEvent


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


def open_samples(self):
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
            self.log('success', 'Successfully removed.')
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
