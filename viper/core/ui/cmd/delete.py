# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os

from viper.common.abstracts import Command
from viper.core.session import __sessions__
from viper.core.database import Database
from viper.core.storage import get_sample_path


class Delete(Command):
    """
    This command deletes the currently opened file (only if it's stored in
    the local repository) and removes the details from the database
    """
    cmd = "delete"
    description = "Delete the opened file"

    def __init__(self):
        super(Delete, self).__init__()

        self.parser.add_argument('-a', '--all', action='store_true', help="Delete ALL files in this project")
        self.parser.add_argument('-f', '--find', action="store_true", help="Delete ALL files from last find")

    def run(self, *args):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        while True:
            choice = input("Are you sure? It can't be reverted! [y/n] ")
            if choice == 'y':
                break
            elif choice == 'n':
                return

        db = Database()

        if args.all:
            if __sessions__.is_set():
                __sessions__.close()

            samples = db.find('all')
            for sample in samples:
                db.delete_file(sample.id)
                os.remove(get_sample_path(sample.sha256))

            self.log('info', "Deleted a total of {} files.".format(len(samples)))
        elif args.find:
            if __sessions__.find:
                samples = __sessions__.find
                for sample in samples:
                    db.delete_file(sample.id)
                    os.remove(get_sample_path(sample.sha256))
                self.log('info', "Deleted {} files.".format(len(samples)))
            else:
                self.log('error', "No find result")

        else:
            if __sessions__.is_set():
                rows = db.find('sha256', __sessions__.current.file.sha256)
                if rows:
                    malware_id = rows[0].id
                    if db.delete_file(malware_id):
                        self.log("success", "File deleted")
                    else:
                        self.log('error', "Unable to delete file")

                os.remove(__sessions__.current.file.path)
                __sessions__.close()

                self.log('info', "Deleted opened file.")
            else:
                self.log('error', "No session open, and no --all argument. Nothing to delete.")
