# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import datetime
import time

from viper.common.objects import File
from viper.common.out import print_error, print_info
from viper.core.database import Database


class Session:
    def __init__(self):
        self.id = None
        # This will be assigned with the File object of the file currently
        # being analyzed.
        self.file = None
        # Timestamp of the creation of the session.
        self.created_at = datetime.datetime.fromtimestamp(time.time()).strftime(
            "%Y-%m-%d %H:%M:%S"
        )


class Sessions:
    def __init__(self):
        self.current = None
        self.__sessions = []
        # Store the results of the last "find" command.
        self.find = None

    def list(self):
        return self.__sessions

    def is_attached_file(self, quiet=False):
        if not self.is_set():
            if not quiet:
                print_error("No session open")
            return False

        if not self.current.file:
            if not quiet:
                print_error("Not attached to a file")
            return False

        return True

    def close(self):
        self.current = None

    def is_set(self):
        # Check if the session has been open or not.
        if self.current:
            return True
        else:
            return False

    def switch(self, session):
        self.current = session
        print_info(
            f"Switched to session #{self.current.id} on {self.current.file.path}"
        )

    def new(self, path=None):
        if not path:
            print_error("You have to open a session on a path")
            return

        session = Session()

        total = len(self.__sessions)
        session.id = total + 1

        # Open a session on the given file.
        session.file = File(path)
        # Try to lookup the file in the database. If it is already present
        # we get its database ID, file name, and tags.
        row = Database().find(key="sha256", value=session.file.sha256)
        if row:
            session.file.id = row[0].id
            session.file.name = row[0].name
            session.file.tags = ", ".join(tag.to_dict()["tag"] for tag in row[0].tag)

            if row[0].parent:
                session.file.parent = "{0} - {1}".format(
                    row[0].parent.name, row[0].parent.sha256
                )
            session.file.children = Database().get_children(row[0].id)

        print_info(f"Session open on {path}")

        # Loop through all existing sessions and check whether there's another
        # session open on the same file and delete it. This is to avoid
        # duplicates in sessions.
        # NOTE: in the future we might want to remove this if sessions have
        # unique attributes (for example, an history just for each of them).
        for entry in self.__sessions:
            if entry.file and entry.file.sha256 == session.file.sha256:
                self.__sessions.remove(entry)

        # Add new session to the list.
        self.__sessions.append(session)
        # Mark the new session as the current one.
        self.current = session


sessions = Sessions()
