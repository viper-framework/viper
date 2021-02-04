# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import time
import datetime

from viper.common.out import print_info, print_error
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

    def is_attached_misp(self, quiet=False):
        if not self.is_set():
            if not quiet:
                print_error("No session opened")
            return False
        if not self.current.misp_event:
            if not quiet:
                print_error("Not attached to a MISP event")
            return False
        return True

    def is_attached_file(self, quiet=False):
        if not self.is_set():
            if not quiet:
                print_error("No session opened")
            return False
        if not self.current.file:
            if not quiet:
                print_error("Not attached to a file")
            return False
        return True

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
        if not path and not misp_event:
            print_error("You have to open a session on a path or on a misp event.")
            return

        session = Session()

        total = len(self.sessions)
        session.id = total + 1

        if path:
            if self.is_set() and misp_event is None and self.current.misp_event:
                session.misp_event = self.current.misp_event

            # Open a session on the given file.
            session.file = File(path)
            # Try to lookup the file in the database. If it is already present
            # we get its database ID, file name, and tags.
            row = Database().find(key='sha256', value=session.file.sha256)
            if row:
                session.file.id = row[0].id
                session.file.name = row[0].name
                session.file.tags = ', '.join(tag.to_dict()['tag'] for tag in row[0].tag)

                if row[0].parent:
                    session.file.parent = '{0} - {1}'.format(row[0].parent.name, row[0].parent.sha256)
                session.file.children = Database().get_children(row[0].id)

            print_info("Session opened on {0}".format(path))

        if misp_event:
            if self.is_set() and path is None and self.current.file:
                session.file = self.current.file
            refresh = False
            if (self.current is not None and self.current.misp_event is not None and
                    self.current.misp_event.event.id is not None and
                    self.current.misp_event.event.id == misp_event.event.id):
                refresh = True
            session.misp_event = misp_event
            if refresh:
                print_info("Session on MISP event {0} refreshed.".format(misp_event.event.id))
            elif not misp_event.event.id:
                print_info("Session opened on a new local MISP event.")
            else:
                print_info("Session opened on MISP event {0}.".format(misp_event.event.id))

        if session.file:
            # Loop through all existing sessions and check whether there's another
            # session open on the same file and delete it. This is to avoid
            # duplicates in sessions.
            # NOTE: in the future we might want to remove this if sessions have
            # unique attributes (for example, an history just for each of them).
            for entry in self.sessions:
                if entry.file and entry.file.sha256 == session.file.sha256:
                    self.sessions.remove(entry)

        # Add new session to the list.
        self.sessions.append(session)
        # Mark the new session as the current one.
        self.current = session


__sessions__ = Sessions()
