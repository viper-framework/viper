# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import getopt

try:
    import pyclamd
    HAVE_CLAMD = True
except ImportError:
    HAVE_CLAMD = False

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __sessions__

class ClamAV(Module):
    cmd = 'clamav'
    description = 'Scan file from local ClamAV daemon'
    authors = ['neriberto']

    def run(self):
        def usage():
            self.log('', "usage: clamav [-h] [-s]")

        def help():
            usage()
            self.log('', "")
            self.log('', "Options:")
            self.log('', "\t--help (-h)\tShow this help message")
            self.log('', "\t--socket(-s)\tSpecify an unix socket (default: Clamd Unix Socket)")
            self.log('', "")

        if not HAVE_CLAMD:
            self.log('error', "Missing dependency, install requests (`pip install pyclamd`)")
            return

        try:
            opts, argv = getopt.getopt(self.args, 'hs:', ['help', 'socket='])
        except getopt.GetoptError as e:
            self.log('', e)
            usage()
            return

        daemon = None
        result = None
        socket = None

        for opt, value in opts:
            if opt in ('-h', '--help'):
                help()
                return
            elif opt in ('-s', '--socket'):
                self.log('info', "Using socket {0} to connect to ClamAV daemon".format(value))
                socket = value
                try:
                    daemon = pyclamd.ClamdUnixSocket(socket)
                except Exception as e:
                    self.log('error', "Daemon connection failure, {0}".format(e))
                    return

        if not __sessions__.is_set():
            self.log('error', "No session opened")
            return

        try:
            if not daemon:
                daemon = pyclamd.ClamdUnixSocket()
                socket = 'Clamav'
        except Exception as e:
            self.log('error', "Daemon connection failure, {0}".format(e))
            return

        try:
            if daemon.ping():
                results = daemon.scan_file(__sessions__.current.file.path)
            else:
                self.log('error', "Unable to connect to the daemon")
        except Exception as e:
            self.log('error', "Unable to scan with antivirus daemon, {0}".format(e))
            return

        found = None
        name = 'not found'

        if results:
            for item in results:
                found = results[item][0]
                name = results[item][1]

        if found == 'ERROR':
            self.log('error', "Check permissions of the binary folder, {0}".format(name))
        else:
            self.log('info', "Daemon {0} returns: {1}".format(socket, name))
