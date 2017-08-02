# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import json

try:
    from pymisp import MISPEvent, EncodeUpdate
    HAVE_PYMISP = True
except:
    HAVE_PYMISP = False

from viper.core.session import __sessions__
from viper.common.objects import MispEvent


def _check_add(self, new_event):
    old_related = self._find_related_id(__sessions__.current.misp_event.event)
    new_related = self._find_related_id(new_event)
    old_related_ids = [i[0] for i in old_related]
    for related, title in new_related:
        if related not in old_related_ids:
            self.log('success', 'New related event: {}/events/view/{} - {}'.format(self.url.rstrip('/'), related, title))
        else:
            self.log('info', 'Related event: {}/events/view/{} - {}'.format(self.url.rstrip('/'), related, title))
    __sessions__.new(misp_event=MispEvent(new_event, self.offline_mode))


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
                    self.args.filename, self.args.sha256))
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
