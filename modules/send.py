import re 
import getopt 
import ftplib
import pysftp

import tempfile, shutil, os

from viper.common.out import *
from viper.common.abstracts import Module 
from viper.core.session import __sessions__

DEFAULT_HOST = '10.0.0.1'
DEFAULT_PROTO = 'sftp'
DEFAULT_USER = 'Administrator'
DEFAULT_PASS = 'secret'
DEFAULT_DIR = '/cygdrive/c/Documents and Settings/Administrator/Desktop'

class Send(Module):
    cmd = 'send'
    description = 'Push file to an analysis host'
    authors = ['Sascha Rommelfangen']

    def __init__(self):
        super(Send, self).__init__()
        self.parser.add_argument('-H', '--host', default=DEFAULT_HOST, help='Host to connect to. Default: ' + DEFAULT_HOST)
        self.parser.add_argument('-P', '--proto', default=DEFAULT_PROTO, help='Protocol to be used (ftp, sftp). Default: ' + DEFAULT_PROTO)
        self.parser.add_argument('-u', '--user', default=DEFAULT_USER, help="Username used for authentication. Default: " + DEFAULT_USER)
        self.parser.add_argument('-p', '--passwd', default=DEFAULT_PASS, help="Password used for authentication. Default: " + DEFAULT_PASS)
        self.parser.add_argument('-D', '--remote', default=DEFAULT_DIR, help="Remote directory. Default: " + DEFAULT_DIR)

    def run(self):
        super(Send, self).run()
        if self.args is None:
            return

        if not __sessions__.is_set():
            self.log('error', "No session opened")
            return 

        host = self.args.host
        proto = self.args.proto
        user = self.args.user
        passwd = self.args.passwd
        remote = self.args.remote
        fpath = __sessions__.current.file.path
        fname = __sessions__.current.file.name
        fname = re.sub(r'[\\\/:\*\?"<>\|]', '_', fname)
        
        if proto == "sftp":
            try:
                sftp = pysftp.Connection(host, username=user, password=passwd) 
                sftp.cd(remote)  
                res = sftp.put(fpath, fname)
            except Exception as e:
                print_error("Unable to sftp sample to host: {}".format(e))
                return
        else:
            fh = open(__sessions__.current.file.path, 'rb')
            try:
                ftp = ftplib.FTP(host)
                #ftp.set_debuglevel(2)
                ftp.login(user,passwd)
                ftp.cwd(remote)
                res = ftp.storbinary('STOR {}'.format(fname), fh)
                ftp.quit()
            except Exception as e:
                print_error("Unable to ftp sample to host: {}".format(e))
                return
        print(res)
