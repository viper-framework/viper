# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

try:
    import pyclamd
    HAVE_CLAMD = True
except ImportError:
    HAVE_CLAMD = False

from viper.common.abstracts import Module
from viper.core.session import __sessions__


class ClamAV(Module):
    cmd = 'clamav'
    description = 'Scan file from local ClamAV daemon'
    authors = ['neriberto']

    def __init__(self):
        super(ClamAV, self).__init__()
        self.parser.add_argument('-s', '--socket', help='Specify an unix socket (default: Clamd Unix Socket)')

    def run(self):
        super(ClamAV, self).run()
        if self.args is None:
            return

        if not HAVE_CLAMD:
            self.log('error', "Missing dependency, install requests (`pip install pyclamd`)")
            return

        if not __sessions__.is_set():
            self.log('error', 'No open session')
            return

        daemon = None
        socket = None
        socket = self.args.socket

        try:
            if socket is not None:
                daemon = pyclamd.ClamdUnixSocket(socket)
                self.log('info', 'Using socket {0} to scan'.format(socket))
            else:
                daemon = pyclamd.ClamdUnixSocket()
                socket = 'Clamav'
        except Exception as ex:
            msg = 'Daemon connection failure, {0}'.format(ex)
            self.log('error,', msg)
            return

        try:
            if daemon.ping():
                with open(__sessions__.current.file.path, 'r') as fd:
                    results = daemon.scan_stream(fd.read())
            else:
                self.log('error', "Unable to connect to the daemon")
        except Exception as ex:
            msg = 'Unable to scan with antivirus daemon, {0}'.format(ex)
            self.log('error', msg)
            return

        found = None
        name = 'not found'

        if results:
            for item in results:
                found = results[item][0]
                name = results[item][1]

        if found == 'ERROR':
            self.log('error', "Check permissions of the binary folder, {0}".format(name))
        else:
            self.log('info', "Daemon {0} returns: {1}".format(socket, name))
