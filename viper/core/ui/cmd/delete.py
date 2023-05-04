# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
from typing import Any

from rich.prompt import Confirm

from viper.common.abstracts import Command
from viper.core.database import Database
from viper.core.sessions import sessions
from viper.core.storage import get_sample_path


class Delete(Command):
    """
    This command deletes the currently open file (only if it's stored in
    the local repository) and removes the details from the database
    """

    cmd = "delete"
    description = "Delete the open file"

    def __init__(self):
        super(Delete, self).__init__()

        self.parser.add_argument(
            "-a", "--all", action="store_true", help="Delete ALL files in this project"
        )
        self.parser.add_argument(
            "-f", "--find", action="store_true", help="Delete ALL files from last find"
        )
        self.parser.add_argument(
            "-y", "--yes", action="store_true", help="Delete without confirmation"
        )

    def run(self, *args: Any):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        if not args.yes:
            if not Confirm.ask("Are you sure? It can't be reverted!"):
                return

        db = Database()

        if args.all:
            if sessions.is_set():
                sessions.close()

            samples = db.find("all")
            for sample in samples:
                db.delete_file(sample.id)
                os.remove(get_sample_path(sample.sha256))

            self.log("info", f"Deleted a total of {len(samples)} files")
        elif args.find:
            if sessions.find:
                samples = sessions.find
                for sample in samples:
                    db.delete_file(sample.id)
                    os.remove(get_sample_path(sample.sha256))

                self.log("info", f"Deleted {len(samples)} files")
            else:
                self.log("error", "No find result")

        else:
            if sessions.is_set():
                rows = db.find("sha256", sessions.current.file.sha256)
                if rows:
                    malware_id = rows[0].id
                    if db.delete_file(malware_id):
                        self.log("success", "File deleted from database")
                    else:
                        self.log("error", "Unable to delete file")

                os.remove(sessions.current.file.path)
                sessions.close()
            else:
                self.log(
                    "error",
                    "No session open, and no --all argument: nothing to delete",
                )
