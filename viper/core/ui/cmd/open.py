# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import tempfile
import argparse

from viper.common.abstracts import Command
from viper.common.network import download
from viper.core.database import Database
from viper.core.storage import get_sample_path
from viper.core.session import __sessions__


class Open(Command):
    """
    This command is used to open a session on a given file.
    It either can be an external file path, or a SHA256 hash of a file which
    has been previously imported and stored.
    While the session is active, every operation and module executed will be
    run against the file specified.
    """
    cmd = "open"
    description = "Open a file"
    fs_path_completion = True

    def __init__(self):
        super(Open, self).__init__()
        self.parser = argparse.ArgumentParser(prog=self.cmd, description=self.description,
                                              epilog="You can also specify a MD5 or SHA256 hash to a previously stored file in order to open a session on it.")

        group = self.parser.add_mutually_exclusive_group()
        group.add_argument('-f', '--file', action='store_true', help="Target is a file")
        group.add_argument('-u', '--url', action='store_true', help="Target is a URL")
        group.add_argument('-l', '--last', action='store_true', help="Target is the entry number from the last find command's results")
        self.parser.add_argument('-t', '--tor', action='store_true', help="Download the file through Tor")
        self.parser.add_argument("value", metavar='PATH, URL, HASH or ID', nargs='*', help="Target to open. Hash can be md5 or sha256. ID has to be from the last search.")

    def run(self, *args):
        try:
            args = self.parser.parse_args(args)
        except SystemExit:
            return

        target = " ".join(args.value)

        if not args.last and target is None:
            self.parser.print_usage()
            return

        # If it's a file path, open a session on it.
        if args.file:
            target = os.path.expanduser(target)

            if not os.path.exists(target) or not os.path.isfile(target):
                self.log('error', "File not found: {0}".format(target))
                return

            __sessions__.new(target)
        # If it's a URL, download it and open a session on the temporary file.
        elif args.url:
            data = download(url=target, tor=args.tor)

            if data:
                tmp = tempfile.NamedTemporaryFile(delete=False)
                tmp.write(data)
                tmp.close()

                __sessions__.new(tmp.name)
        # Try to open the specified file from the list of results from
        # the last find command.
        elif args.last:
            if __sessions__.find:
                try:
                    target = int(target)
                except ValueError:
                    self.log('warning', "Please pass the entry number from the last find to -l/--last (e.g. open -l 5)")
                    return

                for idx, item in enumerate(__sessions__.find, start=1):
                    if idx == target:
                        __sessions__.new(get_sample_path(item.sha256))
                        break
            else:
                self.log('warning', "You haven't performed a find yet")
        # Otherwise we assume it's an hash of an previously stored sample.
        else:
            target = target.strip().lower()

            if len(target) == 32:
                key = 'md5'
            elif len(target) == 64:
                key = 'sha256'
            else:
                self.parser.print_usage()
                return

            db = Database()
            rows = db.find(key=key, value=target)

            if not rows:
                self.log('warning', "No file found with the given hash {0}".format(target))
                return

            path = get_sample_path(rows[0].sha256)
            if path:
                __sessions__.new(path)
