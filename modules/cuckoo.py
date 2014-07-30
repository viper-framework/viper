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
from viper.core.session import __sessions__

class Cuckoo(Module):
    cmd = 'cuckoo'
    description = 'Submit the file to Cuckoo Sandbox'
    authors = ['nex']

    def run(self):
        if not __sessions__.is_set():
            print_error("No session opened")
            return

        if not HAVE_REQUESTS:
            print_error("Missing dependency, install requests (`pip install requests`)")
            return

        def usage():
            print("usage: cuckoo [-H=host] [-p=port] [-m=machine]")

        def help():
            usage()
            print("")
            print("Options:")
            print("\t--help (-h)\tShow this help message")
            print("\t--host (-H)\tSpecify an host (default: localhost)")
            print("\t--port (-p)\tSpecify a port (default: 8090")
            print("\t--machine (-m)\tSpecify a machine (default: unspecified)")
            print("")

        try:
            opts, argv = getopt.getopt(self.args, 'hH:p:m:', ['help', 'host=', 'port=', 'machine='])
        except getopt.GetoptError as e:
            print(e)
            usage()
            return

        host = 'localhost'
        port = 8090
        machine = None

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
            elif opt in ('-m', '--machine'):
                if value:
                    machine = value

        url = 'http://{0}:{1}/tasks/create/file'.format(host, port)

        files = dict(file=open(__sessions__.current.file.path, 'rb'))

        if machine:
            data = {"machine":machine}

        try:
            response = requests.post(url, files=files, data=data)
        except requests.ConnectionError:
            print_error("Unable to connect to Cuckoo API at {0}:{1}".format(host, port))
            return

        print response.text
