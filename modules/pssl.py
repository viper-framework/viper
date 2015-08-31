# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import json

from pypssl import PyPSSL

from viper.common.abstracts import Module

PSSL_URL = ''
PSSL_USER = ''
PSSL_PASS = ''


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

    def query_ip(self, ip):
        result = self.pssl.query(ip)
        for ip, certificates_info in result.items():
            to_print = '{} :\n'.format(ip)
            for sha1 in certificates_info['certificates']:
                to_print += '\t{}\n'.format(sha1)
                if certificates_info['subjects'].get(sha1):
                    for value in certificates_info['subjects'][sha1]['values']:
                        to_print += '\t -> {}\n'.format(value)
            self.log('success', to_print)

    def query_cert(self, sha1):
        result = self.pssl.query_cert(sha1)
        if result.get('hits'):
            to_print = '{} has been seen {} times on:\n'.format(sha1, result['hits'])
            for ip in result['seen'][:5]:
                to_print += '\t{}\n'.format(ip)
            if result['hits'] > 5:
                to_print += '\tOnly show a subsed of the IPs'
            self.log('success', to_print)
        else:
            self.log('error', 'Nothing found')

    def fetch_cert(self, sha1):
        try:
            cert_info = self.pssl.fetch_cert(sha1)
        except Exception as e:
            self.log('error', e)
            return
        to_print = 'Valid: {} -> {}\n'.format(cert_info['info']['not_before'], cert_info['info']['not_after'])
        to_print += '\t{}\n'.format(json.dumps(cert_info['info']['extension'], indent=2))
        to_print += '\tKey Length: {}\n'.format(cert_info['info']['keylength'])
        to_print += '\tFingerprint: {}\n'.format(cert_info['info']['fingerprint'])
        to_print += '\tIssuer: {}\n'.format(cert_info['info']['issuer'])
        to_print += '\tSubject: {}\n'.format(cert_info['info']['subject'])
        to_print += '\tKey: \n{}\n'.format(cert_info['info']['key'])
        to_print += '\tPEM: \n{}\n'.format(cert_info['pem'])

        self.log('success', to_print)

    def run(self):
        super(Pssl, self).run()
        if self.args is None:
            return

        if self.args.url:
            url = self.args.url
        elif PSSL_URL:
            url = PSSL_URL
        else:
            self.log('error', 'You need to give the server to query.')
            return
        if self.args.user:
            user = self.args.user
        else:
            user = PSSL_USER
        if self.args.password:
            password = self.args.password
        else:
            password = PSSL_PASS

        self.pssl = PyPSSL(url, basic_auth=(user, password))

        if self.args.ip:
            self.query_ip(self.args.ip)
        elif self.args.cert:
            self.query_cert(self.args.cert)
        elif self.args.fetch:
            self.fetch_cert(self.args.fetch)
        else:
            self.log('error', 'Please query something...')
