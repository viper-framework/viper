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
            self.log('error', "No session opened")
            return

        if not HAVE_REQUESTS:
            self.log('error', "Missing dependency, install requests (`pip install requests`)")
            return

        def usage():
            self.log('', "usage: cuckoo [-H=host] [-p=port]")

        def help():
            usage()
            self.log('', "")
            self.log('', "Options:")
            self.log('', "\t--help (-h)\tShow this help message")
            self.log('', "\t--host (-H)\tSpecify an host (default: localhost)")
            self.log('', "\t--port (-p)\tSpecify a port (default: 8090")
            self.log('', "")

        try:
            opts, argv = getopt.getopt(self.args, 'hH:p:', ['help', 'host=', 'port='])
        except getopt.GetoptError as e:
            self.log('', e)
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

        files = dict(file=open(__sessions__.current.file.path, 'rb'))

        try:
            response = requests.post(url, files=files)
        except requests.ConnectionError:
            self.log('error', "Unable to connect to Cuckoo API at {0}:{1}".format(host, port))
            return

        print response.text
