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
        self.parser.add_argument('-s', '--submit', action='store_true', help='Submit file or a URL to VirusTotal (by default it only looks up the hash/url)')

        self.parser.add_argument('-i', '--ip', help='IP address to lookup in the passive DNS')
        self.parser.add_argument('-dm', '--domain', help='Domain to lookup in the passive DNS')
        self.parser.add_argument('-u', '--url', help='URL to lookup on VT')

        self.parser.add_argument("-v", "--verbose", action='store_true', help="Turn on verbose mode.")

        self.parser.add_argument('-m', '--misp', default=None, choices=['hashes', 'ips', 'domains', 'urls', 'download'],
                                 help='Searches for the hashes, ips, domains or URLs from the current MISP event, or download the samples if possible.')

    # ######### MISP submodule #########
    def misp(self, option, verbose=False, submit=False):
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
                self.pdns_ip(ip, verbose)
        elif option == "domains":
            domains = __sessions__.current.misp_event.get_all_domains()
            for d in domains:
                self.pdns_domain(d, verbose)
        elif option == "urls":
            urls = __sessions__.current.misp_event.get_all_urls()
            for u in urls:
                self.url(u, verbose, submit)

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

    def url(self, url, verbose=False, submit=False):
        if submit:
            response = self.vt.get_url_report(url, '1')
        else:
            response = self.vt.get_url_report(url)
        if self._has_fail(response):
            return False

        virustotal = response['results']

        if virustotal['response_code'] in [0, -2] or not virustotal.get('scans'):
            self.log('info', "{}: {}".format(bold("VirusTotal message"), virustotal['verbose_msg']))
            return

        if verbose:
            self._display_verbose_scan(virustotal['scans'], url)
        self.log('info', "{} out of {} scans detected {} as malicious.".format(
                 virustotal['positives'], virustotal['total'], bold(url)))
        self.log('info', virustotal['permalink'])

    def _display_verbose_scan(self, scans, query):
        rows = []
        if scans:
            for engine, signature in scans.items():
                if signature['detected']:
                    rows.append([engine, signature['result']])
                    signature = signature['result']

        rows.sort()
        if rows:
            self.log('info', "VirusTotal Report for {}:".format(bold(query)))
            self.log('table', dict(header=['Antivirus', 'Signature'], rows=rows))

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

    def scan(self, to_search, verbose=True, submit=False):
        response = self.vt.get_file_report(to_search)
        if self._has_fail(response):
            return False

        virustotal = response['results']

        if virustotal['response_code'] == 0:
            # Unknown hash
            self.log('info', "{}: {}".format(bold("VirusTotal message"), virustotal['verbose_msg']))
            if submit:
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
            self.log('info', "The file is in the queue and will be processed soon, please try again later")
            return True

        if verbose:
            self._display_verbose_scan(virustotal['scans'], to_search)

        self.log('info', "{} out of {} antivirus detected {} as malicious.".format(virustotal['positives'], virustotal['total'], bold(to_search)))
        return virustotal['md5'], virustotal['sha1'], virustotal['sha256']

    def _prepare_urls(self, detected_urls, verbose):
        if detected_urls:
            res_rows = [(r['scan_date'], r['url'], r['positives'], r['total']) for r in detected_urls]
            res_rows.sort()
            if not verbose:
                res_rows = res_rows[-10:]
            self.log('table', dict(header=['Scan date', 'URL', 'positives', 'total'], rows=res_rows))
        else:
            self.log('warning', 'Nothing has been found.')

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
            self.log('info', "VirusTotal IP resolutions for {}:".format(bold(ip)))
            self.log('table', dict(header=['Last resolved', 'Hostname'], rows=res_rows))
        self.log('info', "VirusTotal Detected URLs for {}:".format(bold(ip)))
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
            self.log('success', "VirusTotal domain resolutions for {}:".format(bold(domain)))
            self.log('table', dict(header=['Last resolved', 'IP Address'], rows=res_rows))
        self.log('info', "VirusTotal Detected URLs for {}:".format(bold(domain)))
        self._prepare_urls(virustotal.get('detected_urls'), verbose)

    def run(self):
        super(VirusTotal, self).run()
        if self.args is None:
            return

        if not HAVE_VT:
            self.log('error', "Missing dependency, install virustotal-api (`pip install virustotal-api`)")
            return

        to_search = None
        if self.args.misp:
            self.misp(self.args.misp, self.args.verbose, self.args.submit)
        elif self.args.ip:
            self.pdns_ip(self.args.ip, self.args.verbose)
        elif self.args.domain:
            self.pdns_domain(self.args.domain, self.args.verbose)
        elif self.args.url:
            self.url(self.args.url, self.args.verbose, self.args.submit)

        elif self.args.search:
            to_search = self.args.search
        elif __sessions__.is_attached_file():
                to_search = __sessions__.current.file.md5

        if to_search:
            self.scan(to_search, self.args.verbose, self.args.submit)
            if self.args.download:
                self.download(to_search, self.args.verbose)

            if self.args.comment:
                response = self.vt.put_comments(to_search, ' '.join(self.args.comment))
                if not self._has_fail(response):
                    self.log('info', ("{}: {}".format(bold("VirusTotal message"), response['results']['verbose_msg'])))
