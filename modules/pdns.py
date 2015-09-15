# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from pypdns import PyPDNS

from viper.common.abstracts import Module

PDNS_URL = ''
PDNS_USER = ''
PDNS_PASS = ''


class Pdns(Module):
    cmd = 'pdns'
    description = 'Query a Passive DNS server'
    authors = ['Raphaël Vinot']

    def __init__(self):
        super(Pdns, self).__init__()
        self.parser.add_argument("--url", help='URL of the Passive DNS server')
        self.parser.add_argument("-u", "--user", help='Username on the PDNS instance')
        self.parser.add_argument("-p", "--password", help='Password on the PDNS instance')
        self.parser.add_argument("query", help='Domain or IP address to query')

    def run(self):
        super(Pdns, self).run()
        if self.args is None:
            return

        if self.args.url:
            url = self.args.url
        elif PDNS_URL:
            url = PDNS_URL
        else:
            self.log('error', 'You need to give the server to query.')
            return
        if self.args.user:
            user = self.args.user
        else:
            user = PDNS_USER
        if self.args.password:
            password = self.args.password
        else:
            password = PDNS_PASS

        pdns = PyPDNS(url.rstrip('/'), (user, password))
        try:
            data = pdns.query(self.args.query)
        except Exception as e:
            self.log('error', e)
            return
        if not data:
            self.log('error', 'Unable to find {}.'.format(self.args.query))
            return
        for d in data:
            self.log('success', "{} -> {} ({} requests)\n\t RR Name: {} - Data: {}".format(
                d['time_first'].strftime("%Y/%m/%d %H:%M"), d['time_last'].strftime("%Y/%m/%d %H:%M"),
                d['count'], d['rrname'], d['rdata']))
