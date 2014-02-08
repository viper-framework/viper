# Copyright (C) 2013-2014 Claudio "nex" Guarnieri.
# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import getopt

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __session__

class Cuckoo(Module):
    cmd = 'cuckoo'
    description = 'Submit the file to Cuckoo Sandbox'

    def run(self):
        if not __session__.is_set():
            print_error("No session opened")
            return

        if not HAVE_REQUESTS:
            print_error("Missing dependency, install requests (`pip install requests`)")
            return

        def usage():
            print("usage: cuckoo [-H=host] [-p=port]")

        def help():
            usage()
            print("")
            print("Options:")
            print("\t--help (-h)\tShow this help message")
            print("\t--host (-H)\tSpecify an host (default: localhost)")
            print("\t--port (-p)\tSpecify a port (default: 8090")
            print("")

        try:
            opts, argv = getopt.getopt(self.args, 'hH:p:', ['help', 'host=', 'port='])
        except getopt.GetoptError as e:
            print(e)
            usage()
            return

        host = 'localhost'
        port = 8090

        for opt, value in opts:
            if opt in ('-h', '--help'):
                help()
                return
            elif opt in ('-H', '--host'):
                if value:
                    host = value
            elif opt in ('-p', '--port'):
                if value:
                    port = value

        url = 'http://{0}:{1}/tasks/create/file'.format(host, port)

        files = dict(file=open(__session__.file.path, 'rb'))

        try:
            response = requests.post(url, files=files)
        except requests.ConnectionError:
            print_error("Unable to connect to Cuckoo API at {0}".format(url))
            return

        print response.text
