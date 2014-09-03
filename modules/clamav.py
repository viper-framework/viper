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
            print("usage: clamav [-h] [-s]")

        def help():
            usage()
            print("")
            print("Options:")
            print("\t--help (-h)\tShow this help message")
            print("\t--socket(-S)\tSpecify an unix socket (default: Clamd Unix Socket)")
            print("")

        if not HAVE_CLAMD:
            print_error("Missing dependency, install requests (`pip install pyclamd`)")
            return

        try:
            opts, argv = getopt.getopt(self.args, 'hs:', ['help', 'socket='])
        except getopt.GetoptError as e:
            print(e)
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
                print_info("Using socket {0} to connect to ClamAV daemon".format(value))
                socket = value
                daemon = pyclamd.ClamdUnixSocket(socket)

        if not __sessions__.is_set():
            print_error("No session opened")
            return

        try:
            if not daemon:
                daemon = pyclamd.ClamdUnixSocket()
                socket = 'Clamav'
        except Exception as e:
            print_error("Daemon connection failure, {0}".format(e))
            return

        try:
            if daemon.ping():
                results = daemon.scan_file(__sessions__.current.file.path)
            else:
                print_error("Unable to connect to the daemon")
        except Exception as e:
            print_error("Unable to scan with antivirus daemon, {0}".format(e))
            return

        found = None
        name = 'not found'

        if results:
            for item in results:
                found = results[item][0]
                name = results[item][1]

        if found == 'ERROR':
            print_error("Check permissions of the binary folder, {0}".format(name))
        else:
            print_info("Daemon {0} returns: {1}".format(socket, name))
