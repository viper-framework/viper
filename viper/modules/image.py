# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from io import BytesIO
import logging

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

from viper.common.out import bold
from viper.common.abstracts import Module
from viper.core.session import __sessions__
from viper.core.config import __config__

log = logging.getLogger('viper')

cfg = __config__


class Image(Module):
    cmd = 'image'
    description = 'Perform analysis on images'
    authors = ['nex']

    def __init__(self):
        super(Image, self).__init__()
        self.parser.add_argument('-g', '--ghiro', action='store_true', help='Upload the file to imageforensic.org and retrieve report')

    def ghiro(self):
        if not HAVE_REQUESTS:
            self.log('error', "Missing dependency, install requests (`pip install requests`)")
            return

        payload = dict(private='true', json='true')
        files = dict(image=BytesIO(__sessions__.current.file.data))

        response = requests.post('http://www.imageforensic.org/api/submit/', data=payload, files=files,
                                 proxies=cfg.http_client.proxies, verify=cfg.http_client.verify, cert=cfg.http_client.cert)
        results = response.json()

        if results['success']:
            report = results['report']

            if len(report['signatures']) > 0:
                self.log('', bold("Signatures:"))

                for signature in report['signatures']:
                    self.log('item', signature['description'])
            for k, v in report.items():
                if k == 'signatures':
                    continue
                if isinstance(v, dict):
                    for k1, v1 in v.items():
                        self.log('info', '{}: {}'.format(k1, v1))
                else:
                    self.log('info', '{}: {}'.format(k, v))

        else:
            self.log('error', "The analysis failed")

    def run(self):
        super(Image, self).run()
        if self.args is None:
            return

        if not __sessions__.is_set():
            self.log('error', "No open session")
            return

        if self.args.ghiro:
            self.ghiro()
        else:
            self.log('error', 'At least one of the parameters is required')
            self.usage()
