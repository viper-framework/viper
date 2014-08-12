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

ATD_USER = None
ATD_PASS = None

class ATD(Module):
    cmd = 'atd'
    description = 'Submit the file to McAfee ATD'
    authors = ['nex']

    def run(self):
        if not __sessions__.is_set():
            print_error("No session opened")
            return

        if not HAVE_REQUESTS:
            print_error("Missing dependency, install requests (`pip install requests`)")
            return

        def usage():
            print("usage: atd [-H=host] [-p=port]")

        def help():
            usage()
            print("")
            print("Options:")
            print("\t--help (-h)\tShow this help message")
            print("\t--host (-H)\tSpecify an host (default: localhost)")
            print("\t--port (-p)\tSpecify a port (default: 443)")
            print("")

        try:
            opts, argv = getopt.getopt(self.args, 'hH:p:', ['help', 'host=', 'port='])
        except getopt.GetoptError as e:
            print(e)
            usage()
            return

        host = 'localhost'
        port = 443

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

        if not ATD_USER or not ATD_PASS:
            choice = raw_input("You need to specify a valid username/password, login now? [y/N] ")
            if choice == 'y':
                username, password = self.authenticate()
            else:
                return
        else:
            username = ATD_USER
            password = ATD_PASS

	creds = base64.b64encode(username + ':' + password)

        url = 'https://{0}:{1}/php/session.php'.format(host, port)
	headers = {'Accept': 'application/vnd.ve.v1.0+json', 'Content-Type': 'application/json', 'VE-SDK-API': creds}


        try:
            response = requests.get(url, headers=headers, verify=False)
        except requests.ConnectionError:
            print_error("Unable to connect to ATD API at {0}:{1}".format(host, port))
            return

	jdata = json.loads(response.text)
	session = base64.b64encode(jdata["results"]["session"] + ':' + jdata["results"]["userId"])

        url = 'https://{0}:{1}/php/fileupload.php'.format(host, port)
	headers = {'Accept': 'application/vnd.ve.v1.0+json', 'VE-SDK-API': session}
        files = {'amas_filename':(__sessions__.current.file.name, open(__sessions__.current.file.path, 'rb'), __sessions__.current.file.mime)}
	data = {"data":'{"data":{}}'}

        try:
            response = requests.post(url, headers=headers, files=files, data=data, verify=False)
        except requests.ConnectionError:
            print_error("Unable to connect to ATD API at {0}:{1}".format(host, port))
            return
	
	if response.status_code == 200:
            print(Sample uploaded successfully)

    def authenticate(self):
        username = raw_input('Username: ')
        password = getpass.getpass('Password: ')

        return (username, password)
