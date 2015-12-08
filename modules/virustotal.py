# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import tempfile
import os

try:
    from virus_total_apis import PublicApi as vt
    from virus_total_apis import PrivateApi as vt_priv
    from virus_total_apis import IntelApi as vt_intel
    HAVE_VT = True
except ImportError:
    HAVE_VT = False

from viper.common.out import bold
from viper.common.abstracts import Module
from viper.core.session import __sessions__
from viper.core.config import Config

cfg = Config()


class VirusTotal(Module):
    cmd = 'virustotal'
    description = 'Lookup the file on VirusTotal'
    authors = ['nex', 'Raphaël Vinot']

    def __init__(self):
        super(VirusTotal, self).__init__()
        if cfg.virustotal.virustotal_has_private_key:
            self.vt = vt_priv(cfg.virustotal.virustotal_key)
        else:
            self.vt = vt(cfg.virustotal.virustotal_key)

        if cfg.virustotal.virustotal_has_intel_key:
            self.vt_intel = vt_intel(cfg.virustotal.virustotal_key)

        self.parser.add_argument('--search', help='Search a hash.')
        self.parser.add_argument('-c', '--comment', nargs='+', help='Comment to add to the file')
        self.parser.add_argument('-d', '--download', action='store_true', help='Hash of the file to download')
        self.parser.add_argument('-s', '--submit', action='store_true', help='Submit file to VirusTotal (by default it only looks up the hash)')

        self.parser.add_argument('-i', '--ip', help='IP address to lookup in the passive DNS')
        self.parser.add_argument('-dm', '--domain', help='Domain to lookup in the passive DNS')

        self.parser.add_argument("-v", "--verbose", action='store_true', help="Turn on verbose mode.")

        self.parser.add_argument('-m', '--misp', default=None, choices=['hashes', 'ips', 'domains', 'download'],
                                 help='Searches for the hashes, ips or domains from the current MISP event, or download the samples if possible.')

    # ######### MISP submodule #########
    def misp(self, option, verbose=False):
        if not __sessions__.is_attached_misp():
            return

        if option == 'hashes':
            ehashes, shashes = __sessions__.current.misp_event.get_all_hashes()
            to_scan = sorted(ehashes + shashes, key=len)
            while to_scan:
                h = to_scan.pop()
                response = self.scan(h, verbose)
                if response and not isinstance(response, bool):
                    to_scan = [eh for eh in to_scan if eh not in response]
        elif option == 'download':
            ehashes, shashes = __sessions__.current.misp_event.get_all_hashes()
            to_dl = sorted(ehashes, key=len)
            while to_dl:
                h = to_dl.pop()
                response = self.scan(h, verbose)
                if not response or isinstance(response, bool):
                    pass
                else:
                    dl = True
                    for sh in shashes:
                        if sh in response:
                            dl = False
                    if not dl:
                        self.log('info', "Sample available on MISP")
                    else:
                        self.download(h, False)
                    to_dl = [eh for eh in to_dl if eh not in response]

        elif option == "ips":
            ips = __sessions__.current.misp_event.get_all_ips()
            for ip in ips:
                self.log('success', bold(ip))
                self.pdns_ip(ip, verbose)
        elif option == "domains":
            domains = __sessions__.current.misp_event.get_all_domains()
            for d in domains:
                self.log('success', bold(d))
                self.pdns_domain(d, verbose)

    # ##################################

    def _has_fail(self, response):
        if isinstance(response, dict):
            # Fail
            if response.get('error'):
                self.log('error', response['error'])
                return True
            return False
        else:
            return False

    def download(self, filehash, open_session=True):
        if cfg.virustotal.virustotal_has_private_key:
            response = self.vt.get_file(filehash)
            if not self._has_fail(response):
                tmp = tempfile.NamedTemporaryFile(delete=False)
                tmp.write(response)
                tmp.close()
                return __sessions__.new(tmp.name)
        elif cfg.virustotal.virustotal_has_intel_key:
            tmpdir = tempfile.mkdtemp()
            response = self.vt_intel.get_file(filehash, tmpdir)
            if not self._has_fail(response):
                if open_session:
                    return __sessions__.new(os.path.join(tmpdir, filehash))
                else:
                    self.log('success', 'Downloaded: {}'.format(os.path.join(tmpdir, filehash)))
        else:
            self.log('error', 'This command requires virustotal private ot intelligence API key')
            return

    def scan(self, to_search, verbose=True):
        response = self.vt.get_file_report(to_search)
        if self._has_fail(response):
            return False

        virustotal = response['results']

        if virustotal['response_code'] == 0:
            # Unknown hash
            self.log('info', "{}: {}".format(bold("VirusTotal message"), virustotal['verbose_msg']))
            if self.args.submit:
                response = self.vt.scan_file(to_search)
                if not self._has_fail(response):
                    self.log('info', "{}: {}".format(bold("VirusTotal message"), response['results']['verbose_msg']))
                    return True
                else:
                    self.log('warning', "{}: {}".format(bold("VirusTotal message"), response['results']['verbose_msg']))
                    return False
            return True
        elif virustotal['response_code'] == -2:
            # Queued for analysis
            self.log('info', "The file is in the que and will be processed soon, please try again later")
            return True

        if not verbose:
            self.log('info', "{} out of {} antivirus detected {} as malicious.".format(virustotal['positives'], virustotal['total'], to_search))

        else:
            rows = []
            if virustotal.get('scans'):
                for engine, signature in virustotal['scans'].items():
                    if signature['detected']:
                        rows.append([engine, signature['result']])
                        signature = signature['result']

            rows.sort()
            if rows:
                self.log('info', "VirusTotal Report for {}:".format(to_search))
                self.log('table', dict(header=['Antivirus', 'Signature'], rows=rows))
                self.log('info', "{} out of {} antivirus detected the sample as malicious.".format(virustotal['positives'], virustotal['total']))

        return virustotal['md5'], virustotal['sha1'], virustotal['sha256']

    def _prepare_urls(self, detected_urls, verbose):
        if detected_urls:
            res_rows = [(r['scan_date'], r['url'], r['positives'], r['total']) for r in detected_urls]
            res_rows.sort()
            if not verbose:
                res_rows = res_rows[-10:]
            self.log('table', dict(header=['Scan date', 'URL', 'positives', 'total'], rows=res_rows))

    def pdns_ip(self, ip, verbose=False):
        response = self.vt.get_ip_report(ip)
        if self._has_fail(response):
            return False
        virustotal = response['results']
        if virustotal.get('resolutions'):
            res_rows = [(r['last_resolved'], r['hostname']) for r in virustotal['resolutions']]
            res_rows.sort()
            if not verbose:
                res_rows = res_rows[-10:]
            self.log('success', "VirusTotal IP resolutions for {}:".format(ip))
            self.log('table', dict(header=['Last resolved', 'Hostname'], rows=res_rows))
        self.log('info', "VirusTotal Detected URLs for {}:".format(ip))
        self._prepare_urls(virustotal.get('detected_urls'), verbose)

    def pdns_domain(self, domain, verbose=False):
        response = self.vt.get_domain_report(domain)
        if self._has_fail(response):
            return False
        virustotal = response['results']
        if virustotal.get('resolutions'):
            res_rows = [(r['last_resolved'], r['ip_address']) for r in virustotal['resolutions']]
            res_rows.sort()
            if not verbose:
                res_rows = res_rows[-10:]
            self.log('success', "VirusTotal domain resolutions for {}:".format(domain))
            self.log('table', dict(header=['Last resolved', 'IP Address'], rows=res_rows))
        self.log('info', "VirusTotal Detected URLs for {}:".format(domain))
        self._prepare_urls(virustotal.get('detected_urls'), verbose)
        self.log('success', virustotal['permalink'])

    def run(self):
        super(VirusTotal, self).run()
        if self.args is None:
            return

        if not HAVE_VT:
            self.log('error', "Missing dependency, install virustotal-api (`pip install virustotal-api`)")
            return

        to_search = None
        if self.args.misp:
            self.misp(self.args.misp, self.args.verbose)
        elif self.args.ip:
            self.pdns_ip(self.args.ip, self.args.verbose)
        elif self.args.domain:
            self.pdns_domain(self.args.domain, self.args.verbose)

        elif self.args.search:
            to_search = self.args.search
        elif __sessions__.is_attached_file():
                to_search = __sessions__.current.file.md5

        if to_search:
            self.scan(to_search, self.args.verbose)
            if self.args.download:
                self.download(to_search, self.args.verbose)

            if self.args.comment:
                response = self.vt.put_comments(to_search, ' '.join(self.args.comment))
                if not self._has_fail(response):
                    self.log('info', ("{}: {}".format(bold("VirusTotal message"), response['results']['verbose_msg'])))
