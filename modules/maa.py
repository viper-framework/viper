# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import getopt
import json
import getpass
import base64

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __sessions__

BC_USER = None
API_KEY = None

class MAA(Module):
    cmd = 'maa'
    description = 'Submit the file to Blue Coat Malware Analysis Appliance'
    authors = ['nex', 'lnmyshkin']

    def run(self):
        if not __sessions__.is_set():
            print_error("No session opened")
            return

        if not HAVE_REQUESTS:
            print_error("Missing dependency, install requests (`pip install requests`)")
            return

        def usage():
            print("usage: maa [-H=host] [-p=port] [-e=env")

        def help():
            usage()
            print("")
            print("Options:")
            print("\t--help (-h)\tShow this help message")
            print("\t--host (-H)\tSpecify an host (default: localhost)")
            print("\t--port (-p)\tSpecify a port (default: 443)")
            print("\t--env (-e)\tSpecify an environment (default: ivm)")
            print("")

        try:
            opts, argv = getopt.getopt(self.args, 'hH:p:e:', ['help', 'host=', 'port=', 'env='])
        except getopt.GetoptError as e:
            print(e)
            usage()
            return

        host = 'localhost'
        port = 443
	env = 'ivm'

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
            elif opt in ('-e', '--env'):
                if value:
                    env = value

        if not API_KEY or not BC_USER:
            choice = raw_input("You need to specify a valid api key, enter one now? [y/N] ")
            if choice == 'y':
                username, apikey = self.authenticate()
            else:
                return
        else:
            username = BC_USER
            apikey = API_KEY


        url = 'https://{0}:{1}/rapi/samples/basic?token={2}'.format(host, port, apikey)
        files = {'upload':(__sessions__.current.file.name, open(__sessions__.current.file.path, 'rb'), __sessions__.current.file.mime)}
	data = {"owner": username}

        try:
            response = requests.post(url, data=data, files=files, verify=False)
        except requests.ConnectionError:
            print_error("Unable to connect to MAA API at {0}:{1}".format(host, port))
            return

	jdata = json.loads(response.text)
	sampleid = jdata["results"][0]["samples_sample_id"]

        url = 'https://{0}:{1}/rapi/tasks?token={2}'.format(host, port, apikey)
	data = {"sample_id": sampleid, "env": env}

        try:
            response = requests.post(url, data=data, verify=False)
        except requests.ConnectionError:
            print_error("Unable to connect to MAA API at {0}:{1}".format(host, port))
            return
	
	print response.text

    def authenticate(self):
        username = raw_input('Username: ')
        password = getpass.getpass('API Key: ')

        return (username, password)
