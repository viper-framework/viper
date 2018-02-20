# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from pypdns import PyPDNS

from viper.common.abstracts import Module
from viper.core.session import __sessions__
from viper.core.config import __config__

cfg = __config__


class Pdns(Module):
    cmd = 'pdns'
    description = 'Query a Passive DNS server'
    authors = ['Raphaël Vinot']

    def __init__(self):
        super(Pdns, self).__init__()
        self.parser.add_argument("--url", help='URL of the Passive DNS server')
        self.parser.add_argument("-u", "--user", help='Username on the PDNS instance')
        self.parser.add_argument("-p", "--password", help='Password on the PDNS instance')
        self.parser.add_argument("query", nargs='?', default=None, help='Domain or IP address to query')

        self.parser.add_argument("-v", "--verbose", action='store_true', help="Turn on verbose mode.")
        self.parser.add_argument('-m', '--misp', default=None, choices=['ips', 'domains'],
                                 help='Searches for the ips or domains from the current MISP event')

    def misp(self, option, verbose=False):
        if not __sessions__.is_attached_misp():
            return

        if option == 'ips':
            ips = __sessions__.current.misp_event.get_all_ips()
            for ip in ips:
                self.query(ip, verbose)
        elif option == 'domains':
            domains = __sessions__.current.misp_event.get_all_domains()
            for d in domains:
                self.query(d, verbose)

    def query(self, q, verbose):
        try:
            data = self.pdns.query(q)
        except Exception as e:
            self.log('error', e)
            return
        if not data:
            self.log('error', 'Nothing found for {}.'.format(q))
            return
        if not verbose:
            data = data[-10:]
        res_rows = [(d['time_first'].strftime("%Y/%m/%d %H:%M"), d['time_last'].strftime("%Y/%m/%d %H:%M"),
                     d['count'], d['rrname'], d['rdata']) for d in data]
        self.log('success', 'Passive DNS for {}:'.format(q))
        self.log('table', dict(header=['First seen', 'Last seen', 'Times seen', 'RR Name', 'Content'], rows=res_rows))

    def run(self):
        super(Pdns, self).run()
        if self.args is None:
            return

        if self.args.url:
            url = self.args.url
        elif cfg.pdns.pdns_url:
            url = cfg.pdns.pdns_url
        else:
            self.log('error', 'You need to give the server to query.')
            return
        if self.args.user:
            user = self.args.user
        else:
            user = cfg.pdns.pdns_user
        if self.args.password:
            password = self.args.password
        else:
            password = cfg.pdns.pdns_pass

        self.pdns = PyPDNS(url.rstrip('/'), (user, password))

        if self.args.misp:
            self.misp(self.args.misp, self.args.verbose)
        else:
            self.query(self.args.query, self.args.verbose)
