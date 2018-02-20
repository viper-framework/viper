# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from pypssl import PyPSSL

from viper.common.abstracts import Module
from viper.core.session import __sessions__
from viper.core.config import __config__

cfg = __config__


class Pssl(Module):
    cmd = 'pssl'
    description = 'Query a Passive SSL server'
    authors = ['Raphaël Vinot']

    def __init__(self):
        super(Pssl, self).__init__()
        self.parser.add_argument("--url", help='URL of the Passive SSL server (No path)')
        self.parser.add_argument("-u", "--user", help='Username on the PSSL instance')
        self.parser.add_argument("-p", "--password", help='Password on the PSSL instance')
        self.parser.add_argument("-i", "--ip", help='IP to query (can be a block, max /23).')
        self.parser.add_argument("-c", "--cert", help='SHA1 of the certificate to search.')
        self.parser.add_argument("-f", "--fetch", help='SHA1 of the certificate to fetch.')

        self.parser.add_argument("-v", "--verbose", action='store_true', help="Turn on verbose mode.")
        self.parser.add_argument('-m', '--misp', default=None, choices=['ips'],
                                 help='Searches for the ips from the current MISP event')

    def misp(self, option):
        if not __sessions__.is_attached_misp():
            return

        if option == 'ips':
            ips = __sessions__.current.misp_event.get_all_ips()
            for ip in ips:
                self.query_ip(ip)

    def query_ip(self, ip):
        try:
            result = self.pssl.query(ip)
        except Exception as e:
            self.log('error', e)
            return
        if not result.items():
            self.log('error', 'Nothing found for {}'.format(ip))
            return
        if result.get('error'):
            self.log('error', result.get('error'))
            return
        for ip, certificates_info in result.items():
            res_rows = []
            for sha1 in certificates_info['certificates']:
                to_append = [sha1]
                if certificates_info['subjects'].get(sha1):
                    to_append.append('\n'.join(certificates_info['subjects'][sha1]['values']))
                else:
                    to_append.append('')
                res_rows.append(to_append)
            self.log('success', 'Passive SSL for {} :'.format(ip))
            self.log('table', dict(header=['SHA1', 'Subjects'], rows=res_rows))

    def query_cert(self, sha1, verbose=False):
        try:
            result = self.pssl.query_cert(sha1)
        except Exception as e:
            self.log('error', e)
            return
        if result.get('hits'):
            self.log('info', '{} has been seen on {} IP adresses'.format(sha1, result['hits']))
            if not verbose:
                r = result['seen'][:10]
            else:
                r = result['seen']
            for ip in r:
                self.log('item', '{}'.format(ip))
            if result['hits'] > 10:
                self.log('warning', 'Certificate seen on too many IPs, only show a subset')
        else:
            self.log('error', 'Nothing found')

    def fetch_cert(self, sha1):
        try:
            cert_info = self.pssl.fetch_cert(sha1)
        except Exception as e:
            self.log('error', e)
            return
        self.log('info', 'Certificate Details - Validity: {} -> {}'.format(cert_info['info']['not_before'], cert_info['info']['not_after']))
        self.log('item', 'Key Length: {}'.format(cert_info['info']['keylength']))
        self.log('item', 'Fingerprint: {}'.format(cert_info['info']['fingerprint']))
        self.log('item', 'Issuer: {}'.format(cert_info['info']['issuer']))
        self.log('item', 'Subject: {}'.format(cert_info['info']['subject']))
        self.log('info', 'Extensions:')
        for key, value in cert_info['info']['extension'].items():
            self.log('item', '{}: {}'.format(key, value.strip()))
        self.log('item', 'Public key: \n{}'.format(cert_info['info']['key']))
        self.log('item', 'PEM: \n{}'.format(cert_info['pem']))

    def run(self):
        super(Pssl, self).run()
        if self.args is None:
            return

        if self.args.url:
            url = self.args.url
        elif cfg.pssl.pssl_url:
            url = cfg.pssl.pssl_url
        else:
            self.log('error', 'You need to give the server to query.')
            return

        # Assuming the backend used is https://github.com/adulau/crl-monitor, the path is set by the API
        url = url.rstrip('/')

        if self.args.user:
            user = self.args.user
        else:
            user = cfg.pssl.pssl_user
        if self.args.password:
            password = self.args.password
        else:
            password = cfg.pssl.pssl_pass

        self.pssl = PyPSSL(url, basic_auth=(user, password))

        if self.args.misp:
            self.misp(self.args.misp)
        elif self.args.ip:
            self.query_ip(self.args.ip)
        elif self.args.cert:
            self.query_cert(self.args.cert, self.args.verbose)
        elif self.args.fetch:
            self.fetch_cert(self.args.fetch)
        else:
            self.log('error', 'Please query something...')
