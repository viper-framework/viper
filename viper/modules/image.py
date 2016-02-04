# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

from viper.common.out import bold
from viper.common.abstracts import Module
from viper.core.session import __sessions__


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
