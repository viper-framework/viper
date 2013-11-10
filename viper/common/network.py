import socket
import urllib2

import socks
#import lib.socks as socks

from viper.common.out import print_error

def download(url, tor=False):
    def create_connection(address, timeout=None, source_address=None):
        sock = socks.socksocket()
        sock.connect(address)
        return sock

    import socket

    if tor:
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, '127.0.0.1', 9050)
        socket.socket = socks.socksocket
        socket.create_connection = create_connection

    try:
        req = urllib2.Request(url)
        req.add_header('User-agent', 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)')
        res = urllib2.urlopen(req)

        data = res.read()
    except urllib2.HTTPError as e:
        print_error(e)
    except urllib2.URLError as e:
        if tor and e.reason.errno == 111:
            print_error("Connection refused, maybe Tor is not running?")
        else:
            print_error(e)
    except Exception as e:
        print_error("Failed download: {0}".format(e))
    else:
        return data
