try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __session__

CUCKOO_HOST = 'localhost'
CUCKOO_PORT = 8090

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

        url = 'http://{0}:{1}/tasks/create/file'.format(CUCKOO_HOST, CUCKOO_PORT)

        files = dict(file=open(__session__.file.path, 'rb'))

        response = requests.post(url, files=files)
        print response.text
