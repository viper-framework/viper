# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os

from viper.common.abstracts import Command
from viper.core.session import __sessions__
from viper.core.project import __project__
from viper.core.database import Database
from viper.core.storage import get_sample_path


class Copy(Command):
    """
    This command copies the opened file into another project. Analysis, Notes
    and Tags are - by default - also copies. Children can (optionally) also
    be copied (recursively).
    """
    cmd = "copy"
    description = "Copy opened file(s) into another project"

    def __init__(self):
        super(Copy, self).__init__()
        self.parser.add_argument('project', type=str, help="Project to copy file(s) to")

        self.parser.add_argument('-d', '--delete', action='store_true', help="delete original file(s) after copy ('move')")
        self.parser.add_argument('--no-analysis', action='store_true', help="do not copy analysis details")
        self.parser.add_argument('--no-notes', action='store_true', help="do not copy notes")
        self.parser.add_argument('--no-tags', action='store_true', help="do not copy tags")

        self.parser.add_argument('-c', '--children', action='store_true', help="also copy all children - if --delete was "
                                                                               "selected also the children will be deleted "
                                                                               "from current project after copy")

    def run(self, *args):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        if not __sessions__.is_set():
            self.log('error', "No open session. This command expects a file to be open.")
            return

        if not __project__.name:
            src_project = "default"
        else:
            src_project = __project__.name

        db = Database()

        db.copied_id_sha256 = []
        res = db.copy(__sessions__.current.file.id,
                      src_project=src_project, dst_project=args.project,
                      copy_analysis=True, copy_notes=True, copy_tags=True, copy_children=args.children)

        if args.delete:
            __sessions__.close()
            for item_id, item_sha256 in db.copied_id_sha256:
                db.delete_file(item_id)
                os.remove(get_sample_path(item_sha256))
                self.log('info', "Deleted: {}".format(item_sha256))

        if res:
            self.log('success', "Successfully copied sample(s)")
            return True
        else:
            self.log('error', "Something went wrong")
            return False
