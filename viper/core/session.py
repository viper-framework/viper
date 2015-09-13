# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import time
import datetime

from viper.common.out import *
from viper.common.objects import File
from viper.core.database import Database

class Session(object):
    def __init__(self):
        self.id = None
        # This will be assigned with the File object of the file currently
        # being analyzed.
        self.file = None
        # Timestamp of the creation of the session.
        self.created_at = datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')
        # MISP event associated to the object
        self.misp_event = None

class Sessions(object):
    def __init__(self):
        self.current = None
        self.sessions = []
        # Store the results of the last "find" command.
        self.find = None

    def close(self):
        self.current = None

    def is_set(self):
        # Check if the session has been opened or not.
        if self.current:
            return True
        else:
            return False

    def switch(self, session):
        self.current = session
        print_info("Switched to session #{0} on {1}".format(self.current.id, self.current.file.path))

    def new(self, path=None, misp_event=None):
        if path is None and misp_event is None:
            print_error("You have to open a session on a path or on a misp event.")
            return

        session = Session()

        total = len(self.sessions)
        session.id = total + 1

        if path is not None:
            if self.is_set() and self.current.misp_event:
                session.misp_event = self.current.misp_event

            # Open a section on the given file.
            session.file = File(path)
            # Try to lookup the file in the database. If it is already present
            # we get file name and
            row = Database().find(key='sha256', value=session.file.sha256)
            if row:
                session.file.name = row[0].name
                session.file.tags = ', '.join(tag.to_dict()['tag'] for tag in row[0].tag)
            print_info("Session opened on {0}".format(path))
        if misp_event is not None:
            if self.is_set() and self.current.file:
                session.file = self.current.file
            refresh = False
            if self.current is not None and self.current.misp_event is not None \
                    and self.current.misp_event.event_id == misp_event.event_id:
                refresh = True
            session.misp_event = misp_event
            if refresh:
                print_info("Session on MISP event {0} refreshed.".format(misp_event.event_id))
            else:
                print_info("Session opened on MISP event {0}.".format(misp_event.event_id))

        if session.file is not None:
            # Loop through all existing sessions and check whether there's another
            # session open on the same file and delete it. This is to avoid
            # duplicates in sessions.
            # NOTE: in the future we might want to remove this if sessions have
            # unique attributes (for example, an history just for each of them).
            for entry in self.sessions:
                if entry.file is not None and entry.file.sha256 == session.file.sha256:
                    self.sessions.remove(entry)

        # Add new session to the list.
        self.sessions.append(session)
        # Mark the new session as the current one.
        self.current = session


__sessions__ = Sessions()
