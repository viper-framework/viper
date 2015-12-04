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
    authors = ['nex']

    def __init__(self):
        super(VirusTotal, self).__init__()
        if cfg.virustotal.virustotal_has_private_key:
            self.vt = vt_priv(cfg.virustotal.virustotal_key)
        else:
            self.vt = vt(cfg.virustotal.virustotal_key)

        if cfg.virustotal.virustotal_has_intel_key:
            self.vt_intel = vt_intel(cfg.virustotal.virustotal_key)

        self.parser.add_argument('-s', '--submit', action='store_true', help='Submit file to VirusTotal (by default it only looks up the hash)')
        self.parser.add_argument('-d', '--download', dest='hash', help='Hash of the file to download')
        self.parser.add_argument('-c', '--comment', nargs='+', help='Comment to add to the file')
        self.parser.add_argument('-i', '--ip', help='IP address to lookup in the passive DNS')
        self.parser.add_argument('-dm', '--domain', help='Domain to lookup in the passive DNS')

        subparsers = self.parser.add_subparsers(dest='subname')
        parser_misp = subparsers.add_parser('misp', help='Query VT with data from a MISP event.')
        parser_misp.add_argument('-mh', '--hashes', action='store_true', help='Query hashes of all the samples')
        parser_misp.add_argument('-ds', '--dsamples', action='store_true', help='Download all possible samples of the MISP event')
        parser_misp.add_argument('-mi', '--mip', action='store_true', help='Query VT passive DNS for all IP listed in the MISP event')
        parser_misp.add_argument('-mdm', '--mdomain', action='store_true', help='Query VT passive DNS for all domains listed in the MISP event')

    # ######### MISP submodule #########
    def misp(self):
        if not __sessions__.is_attached_misp():
            return

        if self.args.hashes:
            ehashes, shashes = __sessions__.current.misp_event.get_all_hashes()
            to_scan = sorted(ehashes + shashes, key=len)
            while to_scan:
                h = to_scan.pop()
                self.log('success', bold(h))
                response = self.scan(h)
                if response and not isinstance(response, bool):
                    to_scan = [eh for eh in to_scan if eh not in response]
        elif self.args.dsamples:
            ehashes, shashes = __sessions__.current.misp_event.get_all_hashes()
            to_dl = sorted(ehashes, key=len)
            while to_dl:
                h = to_dl.pop()
                self.log('success', bold(h))
                response = self.scan(h)
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

        elif self.args.mip:
            ips = [a['value'] for a in __sessions__.current.misp_event.event['Event']['Attribute'] if a['type'] == 'ip-dst']
            for ip in ips:
                self.log('success', bold(ip))
                self.pdns_ip(ip)
        elif self.args.mdomain:
            domains = [a['value'] for a in __sessions__.current.misp_event.event['Event']['Attribute'] if a['type'] == 'domain' or a['type'] == 'hostname']
            for d in domains:
                self.log('success', bold(d))
                self.pdns_domain(d)
            pass

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

    def scan(self, to_search=None):
        if not to_search:
            if __sessions__.is_attached_file():
                to_search = __sessions__.current.file.md5
            else:
                return
        response = self.vt.get_file_report(to_search)
        if self._has_fail(response):
            return False

        virustotal = response['results']
        rows = []
        if virustotal.get('scans'):
            for engine, signature in virustotal['scans'].items():
                if signature['detected']:
                    signature = signature['result']
                else:
                    signature = ''
                rows.append([engine, signature])

        rows.sort()
        if rows:
            self.log('info', "VirusTotal Report:")
            self.log('table', dict(header=['Antivirus', 'Signature'], rows=rows))

            if self.args.submit:
                self.log('', "")
                self.log('info', "The file is already available on VirusTotal, no need to submit")
            return virustotal['md5'], virustotal['sha1'], virustotal['sha256']
        else:
            self.log('info', "The file does not appear to be on VirusTotal yet")

            if self.args.submit:
                response = self.vt.scan_file(to_search)
                if not self._has_fail(response):
                    self.log('info', "{}: {}".format(bold("VirusTotal message"), response['results']['verbose_msg']))
                    return True
        return False

    def _prepare_urls(self, detected_urls):
        if detected_urls:
            res_rows = [(r['scan_date'], r['url'], r['positives'], r['total']) for r in detected_urls]
            res_rows.sort()
            self.log('info', "VirusTotal Detected URLs:")
            self.log('table', dict(header=['Scan date', 'URL', 'positives', 'total'], rows=res_rows))

    def pdns_ip(self, ip):
        response = self.vt.get_ip_report(ip)
        if self._has_fail(response):
            return False
        virustotal = response['results']
        if virustotal.get('resolutions'):
            res_rows = [(r['last_resolved'], r['hostname']) for r in virustotal['resolutions']]
            res_rows.sort()
            self.log('info', "VirusTotal IP resolutions:")
            self.log('table', dict(header=['Last resolved', 'Hostname'], rows=res_rows))
        self._prepare_urls(virustotal.get('detected_urls'))

    def pdns_domain(self, domain):
        response = self.vt.get_domain_report(domain)
        if self._has_fail(response):
            return False
        virustotal = response['results']
        if virustotal.get('resolutions'):
            res_rows = [(r['last_resolved'], r['ip_address']) for r in virustotal['resolutions']]
            res_rows.sort()
            self.log('info', "VirusTotal domain resolutions:")
            self.log('table', dict(header=['Last resolved', 'IP Address'], rows=res_rows))
        self._prepare_urls(virustotal.get('detected_urls'))

    def run(self):
        super(VirusTotal, self).run()
        if self.args is None:
            return

        if not HAVE_VT:
            self.log('error', "Missing dependency, install virustotal-api (`pip install virustotal-api`)")
            return

        if self.args.subname == 'misp':
            self.misp()
            return

        if self.args.hash:
            self.download(self.args.hash)
            return

        if self.args.ip:
            self.pdns_ip(self.args.ip)
            return

        if self.args.domain:
            self.pdns_domain(self.args.domain)
            return

        if not __sessions__.is_set():
            self.log('error', "No session opened")
            return

        if not self.scan():
            # do not try to set a comment if contacting VT failed or if the sample isn't sumbitted
            return

        if self.args.comment:
            response = self.vt.put_comments(__sessions__.current.file.md5, ' '.join(self.args.comment))
            if not self._has_fail(response):
                self.log('info', ("{}: {}".format(bold("VirusTotal message"), response['results']['verbose_msg'])))
