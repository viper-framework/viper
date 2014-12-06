# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __sessions__

class Image(Module):
    cmd = 'image'
    description = 'Perform analysis on images'
    authors = ['nex']

    def ghiro(self):
        if not HAVE_REQUESTS:
            self.log('error', "Missing dependency, install requests (`pip install requests`)")
            return

        payload = dict(private='true', json='true')
        files = dict(image=open(__sessions__.current.file.path, 'rb'))

        response = requests.post('http://www.imageforensic.org/api/submit/', data=payload, files=files)
        results = response.json()

        if results['success']:
            report = results['report']

            if len(report['signatures']) > 0:
                self.log('', bold("Signatures:"))

                for signature in report['signatures']:
                    self.log('item', signature['description'])
        else:
            self.log('error', "The analysis failed")

    def usage(self):
        self.log('', "usage: image <command>")

    def help(self):
        self.usage()
        self.log('', "")
        self.log('', "Options:")
        self.log('', "\tghiro\t\tUpload the file to imageforensic.org and retrieve report")
        self.log('', "")

    def run(self):
        if not __sessions__.is_set():
            self.log('error', "No session opened")
            return

        if len(self.args) == 0:
            self.help()
            return

        if self.args[0] == 'ghiro':
            self.ghiro()
