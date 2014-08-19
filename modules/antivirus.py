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

class Antivirus(Module):
    cmd = 'antivirus'
    description = 'Scan file from session with antivirus Daemon'
    authors = ['neriberto']

    def run(self):
        if not __sessions__.is_set():
            print_error("No session opened")
            return

        if not HAVE_CLAMD:
            print_error("Missing dependency, install requests (`pip install pyclamd`)")
            return

        def usage():
            print("usage: antivirus [-S=UnixSocket]")

        def help():
            usage()
            print("")
            print("Options:")
            print("\t--help (-h)\tShow this help message")
            print("\t--socket(-S)\tSpecify an unix socket (default: Clamd Unix Socket)")
            print("")

        try:
            opts, argv = getopt.getopt(self.args, 'hS:', ['help', 'socket='])
        except getopt.GetoptError as e:
            print(e)
            usage()
            return

        Daemon = None
        result = None
        socket = None

        for opt, value in opts:
            if opt in ('-h', '--help'):
                help()
                return
            elif opt in ('-S', '--socket'):
                if value:
                    socket = value
                    print "Using socket {0} to connect in antivirus daemon".format(value)
                    Daemon = pyclamd.ClamdUnixSocket(value)

        try:
            if Daemon == None:
                Daemon = pyclamd.ClamdUnixSocket()
                socket = "Clamav"
            if Daemon == None:
                 print_error("Daemon connection failure")
        except Exception as e:
            print_error("Daemon connection failure, {0}".format(e))

        try:
            if Daemon.ping():
                result = Daemon.scan_file(__sessions__.current.file.path)
            else:
                print_error("Daemon is offline")
        except Exception as e:
                print_error("Unable to scan with antivirus daemon, {0}".format(e))

        found = None
        name = "not found"

        if result != None:
            for item in result:
                found = result[item][0]
                name = result[item][1]

        if found == "ERROR":
            print_error("Check the permission on binaries folder to the daemon, {0}".format(name))
        else:
            print "Daemon {0} returns : {1}".format(socket, name)
