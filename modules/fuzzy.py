# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os
import getopt

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.database import Database
from viper.core.session import __sessions__

try:
    import pydeep
    HAVE_PYDEEP = True
except ImportError:
    HAVE_PYDEEP = False

class Fuzzy(Module):
    cmd = 'fuzzy'
    description = 'Search for similar files through fuzzy hashing'
    authors = ['nex']

    def run(self):
        if not __sessions__.is_set():
            self.log('error', "No session opened")
            return

        if not HAVE_PYDEEP:
            self.log('error', "Missing dependency, install pydeep (`pip install pydeep`)")
            return

        if not __sessions__.current.file.ssdeep:
            self.log('error', "No ssdeep hash available for opened file")
            return

        def usage():
            self.log('', "usage: fuzzy [-v]")

        def help():
            usage()
            self.log('', "")
            self.log('', "Options:")
            self.log('', "\t--help (-h)\tShow this help message")
            self.log('', "\t--verbose (-v)\tPrints verbose logging")
            self.log('', "")

        arg_verbose = False

        try:
            opts, argv = getopt.getopt(self.args[0:], 'hv', ['help', 'verbose'])
        except getopt.GetoptError as e:
            self.log('error', e)
            return

        for opt, value in opts:
            if opt in ('-h', '--help'):
                help()
                return
            elif opt in ('-v', '--verbose'):
                arg_verbose = True

        db = Database()
        samples = db.find(key='all')

        matches = []
        for sample in samples:
            if sample.sha256 == __sessions__.current.file.sha256:
                continue

            if not sample.ssdeep:
                continue

            score = pydeep.compare(__sessions__.current.file.ssdeep, sample.ssdeep)
            if score > 40:
                matches.append(['{0}%'.format(score), sample.name, sample.sha256])

            if arg_verbose:
                self.log('info', "Match {0}%: {2} [{1}]".format(score, sample.name, sample.sha256))

        self.log('info', "{0} relevant matches found".format(bold(len(matches))))

        if len(matches) > 0:
            self.log('table', dict(header=['Score', 'Name', 'SHA256'], rows=matches))
