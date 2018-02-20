# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import glob
import shutil
import logging
import json

try:
    from virus_total_apis import PublicApi as vt
    from virus_total_apis import PrivateApi as vt_priv
    from virus_total_apis import IntelApi as vt_intel

    HAVE_VT = True
except ImportError:
    HAVE_VT = False

from viper.common.out import bold
from viper.common.abstracts import Module
from viper.common.objects import MispEvent
from viper.core.session import __sessions__
from viper.core.project import __project__
from viper.core.config import __config__

log = logging.getLogger('viper')

cfg = __config__
cfg.parse_http_client(cfg.virustotal)


class VirusTotal(Module):
    cmd = 'virustotal'
    description = 'Lookup the file on VirusTotal'
    authors = ['nex', 'Raphaël Vinot']

    def __init__(self):
        super(VirusTotal, self).__init__()
        if not HAVE_VT:
            self.log('error', "Missing dependency, install virustotal-api (`pip install virustotal-api`)")
            return
        self.cur_path = __project__.get_path()
        if cfg.virustotal.virustotal_has_private_key:
            self.vt = vt_priv(cfg.virustotal.virustotal_key, proxies=cfg.virustotal.proxies)
        else:
            self.vt = vt(cfg.virustotal.virustotal_key, proxies=cfg.virustotal.proxies)

        if cfg.virustotal.virustotal_has_intel_key:
            self.vt_intel = vt_intel(cfg.virustotal.virustotal_key, proxies=cfg.virustotal.proxies)

        self.parser.add_argument('--search', help='Search a hash.')
        self.parser.add_argument('-c', '--comment', nargs='+', help='Comment to add to the file')
        self.parser.add_argument('-d', '--download', action='store_true', help='Hash of the file to download')
        self.parser.add_argument('-dl', '--download_list', action='store_true', help='List the downloaded files')
        self.parser.add_argument('-do', '--download_open', type=int, help='Open a file from the list of the DL files (ID)')
        self.parser.add_argument('-don', '--download_open_name', help='Open a file by name from the list of the DL files (NAMe)')
        self.parser.add_argument('-dd', '--download_delete', help='Delete a file from the list of the DL files can be an ID or all.')
        self.parser.add_argument('-s', '--submit', action='store_true', help='Submit file or a URL to VirusTotal (by default it only looks up the hash/url)')  # noqa

        self.parser.add_argument('-i', '--ip', help='IP address to lookup in the passive DNS')
        self.parser.add_argument('-dm', '--domain', help='Domain to lookup in the passive DNS')
        self.parser.add_argument('-u', '--url', help='URL to lookup on VT')

        self.parser.add_argument("-v", "--verbose", action='store_true', help="Turn on verbose mode.")

        self.parser.add_argument('-m', '--misp', default=None,
                                 choices=['hashes', 'ips', 'domains', 'urls', 'download', 'download_all'],
                                 help='Searches for the hashes, ips, domains or URLs from the current MISP event, '
                                      'or download the samples if possible. Be carefull with download_all: it will '
                                      'download *all* the samples of all the MISP events in the current project.')

    def _get_local_events(self, path):
        return [json.loads(open(p, 'r').read()) for p in glob.glob(os.path.join(path, '*'))]

    def _download_hashes(self, misp_event, verbose):
        eid = misp_event.event.id
        ehashes, shashes = misp_event.get_all_hashes()
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
                    self.download(h, False, eid, verbose)
                to_dl = [eh for eh in to_dl if eh not in response]

    # ######### MISP submodule #########
    def misp(self, option, verbose=False, submit=False):
        if option == 'download_all':
            for event in self._get_local_events(os.path.join(self.cur_path, 'misp_events')):
                self._download_hashes(MispEvent(event), False)
            return

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
            self._download_hashes(__sessions__.current.misp_event, verbose)
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
        self.log('info', "{} out of {} scans detected {} as malicious.".format(virustotal['positives'], virustotal['total'], bold(url)))
        self.log('info', virustotal['permalink'])

    def _display_verbose_scan(self, virustotal, query):
        self.log('success', "VirusTotal Report for {}:".format(bold(query)))
        if 'times_submitted' in virustotal and 'first_seen' in virustotal:
            self.log('info', 'Submitted {} times and seen first on {}.'.format(virustotal['times_submitted'], virustotal['first_seen']))

        if 'submission_names' in virustotal:
            self.log('info', 'Known names:')
            for item in virustotal['submission_names']:
                self.log('item', item)

        rows = []
        if 'scans' in virustotal:
            for engine, signature in virustotal['scans'].items():
                if signature['detected']:
                    rows.append([engine, signature['result']])
                    signature = signature['result']
        rows.sort()
        if rows:
            self.log('info', "Detecting engines:")
            self.log('table', dict(header=['Antivirus', 'Signature'], rows=rows))

    # ####### Helpers for open ########

    def _load_tmp_samples(self):
        tmp_samples = []
        samples_path = os.path.join(self.cur_path, 'vt_samples')
        path = os.path.join(samples_path, '*')
        for p in glob.glob(path):
            if os.path.basename(p).isdigit():
                eid = os.path.basename(p)
                fullpath = os.path.join(samples_path, eid, '*')
                for p in glob.glob(fullpath):
                    name = os.path.basename(p)
                    tmp_samples.append((eid, p, name))
            else:
                for p in glob.glob(p):
                    name = os.path.basename(p)
                    if not os.path.basename(p).isdigit():
                        tmp_samples.append(('', p, name))
        return tmp_samples

    def _display_tmp_files(self):
        cureid = None
        if __sessions__.is_attached_misp(True):
            cureid = __sessions__.current.misp_event.event.id
        header = ['Sample ID', 'Current', 'Event ID', 'Filename']
        rows = []
        i = 0
        tmp_samples = self._load_tmp_samples()
        if len(tmp_samples) == 0:
            self.log('warning', 'No temporary samples available.')
            return
        for eid, path, name in tmp_samples:
            if eid == cureid:
                rows.append((i, '*', eid, name))
            else:
                rows.append((i, '', eid, name))
            i += 1
        self.log('table', dict(header=header, rows=rows))

    def _clean_tmp_samples(self, eid):
        to_remove = os.path.join(self.cur_path, 'vt_samples')
        if eid != 'all':
            to_remove = os.path.join(to_remove, eid)
        if os.path.exists(to_remove):
            shutil.rmtree(to_remove)
            return True
        return False

    # ##########################################

    def download(self, filehash, open_session=True, force_eid=None, verbose=True):
        # FIXME: private and intel API are inconsistent to save a file.
        samples_path = os.path.join(self.cur_path, 'vt_samples')
        if __sessions__.is_attached_misp(True):
            samples_path = os.path.join(samples_path, __sessions__.current.misp_event.event.id)
        elif force_eid:
            samples_path = os.path.join(samples_path, str(force_eid))

        if not os.path.exists(samples_path):
            os.makedirs(samples_path)

        filename = os.path.join(samples_path, filehash)
        if os.path.exists(filename):
            self.log('info', '{} has already been downloaded.'.format(filehash))
            return

        if cfg.virustotal.virustotal_has_private_key:
            response = self.vt.get_file(filehash)
            if not self._has_fail(response):
                with open(filename, 'w') as f:
                    f.write(response)
            else:
                return

        elif cfg.virustotal.virustotal_has_intel_key:
            response = self.vt_intel.get_file(filehash, samples_path)
            if self._has_fail(response):
                return
        else:
            self.log('error', 'This command requires virustotal private ot intelligence API key')
            return

        if open_session:
            return __sessions__.new(filename)
        self.log('success', 'Successfully downloaded {}'.format(filehash))
        if verbose:
            self._display_tmp_files()

    def scan(self, to_search, verbose=True, submit=False, path_to_submit=None):
        response = self.vt.get_file_report(to_search)
        if self._has_fail(response):
            return False

        virustotal = response['results']

        if virustotal['response_code'] == 0:
            # Unknown hash
            self.log('info', "{}: {}".format(bold("VirusTotal message"), virustotal['verbose_msg']))
            if submit and path_to_submit:
                response = self.vt.scan_file(path_to_submit)
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
            self._display_verbose_scan(virustotal, to_search)

        self.log('info', "{} out of {} antivirus detected {} as malicious.".format(virustotal['positives'], virustotal['total'], bold(to_search)))
        self.log('info', virustotal['permalink'] + '\n')
        return virustotal['md5'], virustotal['sha1'], virustotal['sha256']

    def _prepare_urls(self, query, detected_urls, verbose):
        if detected_urls:
            self.log('success', "VirusTotal Detected URLs for {}:".format(bold(query)))
            res_rows = [(r['scan_date'], r['url'], r['positives'], r['total']) for r in detected_urls]
            res_rows.sort()
            if not verbose:
                res_rows = res_rows[-10:]
            self.log('table', dict(header=['Scan date', 'URL', 'positives', 'total'], rows=res_rows))
        else:
            self.log('warning', 'No URLs found for {}.'.format(bold(query)))

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
            self.log('success', "VirusTotal IP resolutions for {}:".format(bold(ip)))
            self.log('table', dict(header=['Last resolved', 'Hostname'], rows=res_rows))
        else:
            self.log('warning', 'No resolutions found for {}.'.format(bold(ip)))
        self._prepare_urls(ip, virustotal.get('detected_urls'), verbose)
        self.log('info', 'https://www.virustotal.com/en/ip-address/{}/information/\n'.format(ip))

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
        else:
            self.log('warning', 'No resolutions found for {}.'.format(bold(domain)))
        self._prepare_urls(domain, virustotal.get('detected_urls'), verbose)
        self.log('info', 'https://www.virustotal.com/en/domain/{}/information/\n'.format(domain))

    def run(self):
        super(VirusTotal, self).run()
        if self.args is None:
            return

        if not HAVE_VT:
            self.log('error', "Missing dependency, install virustotal-api (`pip install virustotal-api`)")
            return

        to_search = None
        path_to_submit = None
        if self.args.misp:
            self.misp(self.args.misp, self.args.verbose, self.args.submit)
        elif self.args.ip:
            self.pdns_ip(self.args.ip, self.args.verbose)
        elif self.args.domain:
            self.pdns_domain(self.args.domain, self.args.verbose)
        elif self.args.url:
            self.url(self.args.url, self.args.verbose, self.args.submit)
        elif self.args.download_list:
            self._display_tmp_files()
        elif self.args.download_open is not None:
            tmp_samples = self._load_tmp_samples()
            try:
                eid, path, name = tmp_samples[self.args.download_open]
                if eid:
                    if __sessions__.is_attached_misp(quiet=True):
                        if __sessions__.current.misp_event.event.id != int(eid):
                            self.log('warning', 'You opened a sample related to a MISP event different than the one you are currently connected to: {}.'.format(eid))  # noqa
                        else:
                            self.log('success', 'You opened a sample related to the current MISP event.')
                    else:
                        self.log('warning', 'This samples is linked to the MISP event {eid}. You may want to run misp pull {eid}'.format(eid=eid))  # noqa
                return __sessions__.new(path)
            except IndexError:
                self.log('error', 'Invalid id, please use virustotal -dl.')
        elif self.args.download_open_name is not None:
            tmp_samples = self._load_tmp_samples()
            try:
                for tmp_sample in tmp_samples:
                    eid, path, name = tmp_sample
                    if name == self.args.download_open_name:
                        if eid:
                            if __sessions__.is_attached_misp(quiet=True):
                                if __sessions__.current.misp_event.event.id != int(eid):
                                    self.log('warning', 'You opened a sample related to a MISP event different than the one you are currently connected to: {}.'.format(eid))  # noqa
                                else:
                                    self.log('success', 'You opened a sample related to the current MISP event.')
                            else:
                                self.log('warning', 'This samples is linked to the MISP event {eid}. You may want to run misp pull {eid}'.format(eid=eid))  # noqa
                        return __sessions__.new(path)
            except IndexError:
                self.log('error', 'Invalid id, please use virustotal -dl.')
        elif self.args.download_delete is not None:
            if self.args.download_delete == 'all':
                samples_path = os.path.join(self.cur_path, 'vt_samples')
                if os.path.exists(samples_path):
                    shutil.rmtree(samples_path)
                    self.log('success', 'Successfully removed {}'.format(samples_path))
                else:
                    self.log('error', '{} does not exists'.format(samples_path))
            else:
                tmp_samples = self._load_tmp_samples()
                try:
                    eid, path, name = tmp_samples[int(self.args.download_delete)]
                    os.remove(path)
                    self.log('success', 'Successfully removed {}'.format(path))
                except Exception:
                    self.log('error', 'Invalid id, please use virustotal -dl.')
        elif self.args.search:
            to_search = self.args.search
        elif __sessions__.is_attached_file():
            to_search = __sessions__.current.file.md5

        if self.args.submit and __sessions__.is_attached_file():
            path_to_submit = __sessions__.current.file.path

        if to_search:
            self.scan(to_search, self.args.verbose, self.args.submit, path_to_submit)
            if self.args.download:
                self.download(to_search, self.args.verbose)

            if self.args.comment:
                response = self.vt.put_comments(to_search, ' '.join(self.args.comment))
                if not self._has_fail(response):
                    self.log('info', ("{}: {}".format(bold("VirusTotal message"), response['results']['verbose_msg'])))
