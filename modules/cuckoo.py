# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

from viper.common.abstracts import Module
from viper.core.session import __sessions__


class Cuckoo(Module):
    cmd = 'cuckoo'
    description = 'Submit the file to Cuckoo Sandbox'
    authors = ['nex']

    def __init__(self):
        super(Cuckoo, self).__init__()
        self.parser.add_argument('-H', '--host', default='localhost', help='Specify an host. Default: localhost')
        self.parser.add_argument('-p', '--port', default=8090, type=int, help='Specify an port. Default: 8090')

    def run(self):
        super(Cuckoo, self).run()
        if self.args is None:
            return

        if not __sessions__.is_set():
            self.log('error', "No session opened")
            return

        if not HAVE_REQUESTS:
            self.log('error', "Missing dependency, install requests (`pip install requests`)")
            return

        host = self.args.host
        port = self.args.port

        url = 'http://{0}:{1}/tasks/create/file'.format(host, port)

        files = dict(file=open(__sessions__.current.file.path, 'rb'))

        try:
            response = requests.post(url, files=files)
        except requests.ConnectionError:
            self.log('error', "Unable to connect to Cuckoo API at {0}:{1}".format(host, port))
            return
