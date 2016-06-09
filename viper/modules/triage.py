# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from viper.common.abstracts import Module
from viper.core.database import Database
from viper.core.session import __sessions__

class Triage(Module):
    cmd = 'triage'
    description = "Perform some initial triaging and tagging of the file"
    authors = ['nex']

    def __init__(self):
        super(Triage, self).__init__()

        self.parser.add_argument('-a', '--all', action='store_true',
            help="Triage all files")

    def _triage_file_type(self, obj):
        tags = []

        # TODO: extend this triaging with as many relevant tags as possible.
        # For example, avoid "exe" or other too common or obvious attributes.
        if 'PE32' in obj.type:
            if 'DLL' in obj.type:
                self.log('info', "{} is a DLL".format(obj.name))
                tags.append('dll')
            elif 'native' in obj.type:
                self.log('info', "{} is a Windows driver".format(obj.name))
                tags.append('driver')        

        return tags

    def run(self):
        super(Triage, self).run()
        db = Database()

        if self.args and self.args.all:
            samples = db.find(key='all')

            for sample in samples:
                tags = []
                tags.extend(self._triage_file_type(sample))

                db.add_tags(sample.sha256, tags)
        # We're running against the already opened file.
        else:
            if not __sessions__.is_set():
                self.log('error', "No open session")
                return

            tags = []
            tags.extend(self._triage_file_type(__sessions__.current.file))

            db.add_tags(__sessions__.current.file.sha256, tags)
