# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import requests
from requests import ConnectionError
from viper.common.out import print_error


def download(url, tor=False):
    s = requests.Session()
    s.headers.update({'User-agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)'})
    proxies = {}
    if tor:
        proxies = {'http': 'socks5://{}:{}'.format('127.0.0.1', 9050),
                   'https': 'socks5://{}:{}'.format('127.0.0.1', 9050)}
    try:
        res = s.get(url, proxies=proxies)
        res.raise_for_status()
    except ConnectionError as e:
        if tor:
            print_error("Connection refused, maybe Tor is not running?")
        print_error(e)
    except Exception as e:
        print_error("Failed download: {0}".format(e))
    else:
        return res.content
