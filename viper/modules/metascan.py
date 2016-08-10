# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

import json
import time

from viper.common.utils import string_clean
from viper.common.abstracts import Module
from viper.core.session import __sessions__
from viper.core.config import Config


cfg = Config()


class Metascan(Module):
    cmd = 'metascan'
    description = 'Submits a file to a private Metascan A/V scanner and reports the results.'
    authors = ['Christophe Vandeplas']

    def __init__(self):
        super(Metascan, self).__init__()
        self.parser.add_argument("-v", "--verbose", action='store_true', help="Turn on verbose mode.")
        self.metascan_url = ''

    def submit(self):
        headers = {'filename': __sessions__.current.file.name}
        payload = open(__sessions__.current.file.path, 'ro')
        r = requests.post(self.metascan_url + '/metascan_rest/file', headers=headers, data=payload)
        r_json = json.loads(r.text)
        return r_json['data_id']

    def check_result(self, data_id):
        r = requests.get(self.metascan_url + '/metascan_rest/file/' + data_id)
        return json.loads(r.text)

    def poll_result(self, data_id):
        while True:
            r_json = self.check_result(data_id)
            if r_json['scan_results']['in_queue'] == 1:
                # need to poll again
                time.sleep(0.5)
            elif r_json['scan_results']['in_queue'] == 0:
                return r_json
            else:
                self.log('error', 'Unexpected result in poll request for data_id={}'.format(data_id))
                return

    def prepare(self):
        if not cfg.metascan.metascan_url:
            choice = raw_input("You need to specify the Metascan private URL, enter now? [y/N] ")
            if choice == 'y':
                self.metascan_url = raw_input('Metascan URL: ')
            else:
                return
        else:
            self.metascan_url = cfg.metascan.metascan_url

    def run(self):
        super(Metascan, self).run()

        if not HAVE_REQUESTS:
            self.log('error', "Missing dependencies (`pip install requests`)")
            return

        if not __sessions__.is_attached_file():
            self.log('error', "No open session")
            return

        self.prepare()
        try:
            data_id = self.submit()
            result = self.poll_result(data_id)

            report = []
            hits = 0
            for scanner in result['scan_results']['scan_details']:
                item = result['scan_results']['scan_details'][scanner]
                if item['scan_result_i'] == 1 or self.args.verbose:
                    report.append([scanner, string_clean(item['threat_found']), item['def_time'].replace('T00:00:00Z', '')])
                if item['scan_result_i'] == 1:
                    hits += 1

            if not report:
                self.log('info', "Not detected by the {} A/V engines.".format(len(result['scan_results']['scan_details'])))
            else:
                self.log('table', dict(
                    header=['Engine', 'Threat Name', 'Definition'],
                    rows=report
                ))
                self.log('info', "Detected by {}/{} A/V engines:".format(hits, len(result['scan_results']['scan_details'])))
        except:
            self.log('info', "Error while connecting to metascan server.")
            return
