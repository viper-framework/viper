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


def create_event(self):
    if self.args.threat is not None:
        # Dirty trick to keep consistency in the module: the threat level in the upload
        # API can go from 0 import to 3 but it is 1 to 4 in the event mgmt API.
        # It will be fixed in a near future, in the meantime, we do that:
        self.args.threat += 1

    if not self.args.info:
        self.log('error', 'Info field is required for a new event')
    info = ' '.join(self.args.info)

    # Check if the following arguments have been set (and correctly set). If not, take the config values
    self.args.distrib = self.distribution if self.args.distrib is None else self.args.distrib
    self.args.sharing = self.sharinggroup if self.args.sharing is None else self.args.sharing

    if self.args.sharing and self.args.distrib != 4:
        self.args.sharing = None
        self.log('info', "Sharing group can only be set if distribution is 4. Clearing set value")

    misp_event = MISPEvent()
    misp_event.set_all_values(info=info, distribution=self.args.distrib,
                              sharing_group_id=self.args.sharing, threat_level_id=self.args.threat,
                              analysis=self.args.analysis, date=self.args.date)
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
