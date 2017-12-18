# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

try:
    import pyclamd
    HAVE_CLAMD = True
except ImportError:
    HAVE_CLAMD = False

import os

from viper.common.abstracts import Module
from viper.core.database import Database
from viper.core.session import __sessions__


class ClamAV(Module):
    cmd = 'clamav'
    description = 'Scan file from local ClamAV daemon'
    authors = ['neriberto']

    def __init__(self):
        super(ClamAV, self).__init__()
        self.parser.add_argument('-s', '--socket', help='Specify an unix socket (default: Clamd Unix Socket)')
        self.parser.add_argument('-a', '--all', action='store_true', help='Scan all files')
        self.parser.add_argument('-t', '--tag', action='store_true', help='Tag file(s) with the signature name when detect as malware')
        self.db = Database()

    def run(self):
        super(ClamAV, self).run()
        if self.args is None:
            return

        if not HAVE_CLAMD:
            self.log('error', "Missing dependency, install pyclamd (`pip install pyclamd`)")
            return

        if not self.Connect():
            self.log('error', 'Daemon is not responding!')
            return

        if not __sessions__.is_set():
            if self.args.all:
                self.ScanAll()
            else:
                self.log('error', 'No open session')
        else:
            self.ScanFile(__sessions__.current.file)

    def ScanAll(self):
        samples = self.db.find(key='all')
        for sample in samples:
            if sample.size == 0:
                continue
            self.ScanFile(sample)

    def Connect(self):
        self.daemon = None
        self.socket = self.args.socket
        try:
            if self.socket is not None:
                self.daemon = pyclamd.ClamdUnixSocket(self.socket)
                self.log('info', 'Using socket {0} to scan'.format(self.socket))
            else:
                self.daemon = pyclamd.ClamdUnixSocket()
                self.socket = 'Clamav'

            return self.daemon.ping()
        except Exception as ex:
            msg = 'Daemon connection failure, {0}'.format(ex)
            self.log('error,', msg)
            return False

    def ScanFile(self, session_file):

        if not os.path.exists(session_file.path):
            self.log('error', 'The file does not exists at path {0}'.format(session_file.path))
            return

        try:
            if self.daemon.ping():
                with open(session_file.path, 'rb') as fd:
                    results = self.daemon.scan_stream(fd.read())
            else:
                self.log('error', "Unable to connect to the daemon")
        except Exception as ex:
            msg = 'Unable to scan file {0} with antivirus daemon, {1}'.format(session_file.sha256, ex)
            self.log('error', msg)
            return

        found = None
        name = None

        if results:
            for item in results:
                found = results[item][0]
                name = results[item][1]

        if found == 'ERROR':
            self.log('error', "Check permissions of the binary folder, {0}".format(name))
        else:
            if name is not None:
                if self.args.tag:
                    self.db.add_tags(session_file.sha256, name)
            else:
                name = 'Threat not found!'

            self.log('info', "{0} identify {1} as : {2}".format(self.socket, session_file.sha256, name))
