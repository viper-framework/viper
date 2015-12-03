# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import tempfile

try:
    from virus_total_apis import PublicApi as vt
    from virus_total_apis import PrivateApi as vt_priv
    from virus_total_apis import IntelApi as vt_intel
    HAVE_VT = True
except ImportError:
    HAVE_VT = False

from viper.common.out import bold
from viper.common.abstracts import Module
from viper.core.session import __sessions__
from viper.core.config import Config

cfg = Config()


class VirusTotal(Module):
    cmd = 'virustotal'
    description = 'Lookup the file on VirusTotal'
    authors = ['nex']

    def __init__(self):
        super(VirusTotal, self).__init__()
        if cfg.virustotal.virustotal_has_private_key:
            self.vt = vt_priv(cfg.virustotal.virustotal_key)
        else:
            self.vt = vt(cfg.virustotal.virustotal_key)

        if cfg.virustotal.virustotal_has_intel_key:
            self.vt_intel = vt_intel(cfg.virustotal.virustotal_key)

        self.parser.add_argument('-s', '--submit', action='store_true', help='Submit file to VirusTotal (by default it only looks up the hash)')
        self.parser.add_argument('-d', '--download', action='store', dest='hash')
        self.parser.add_argument('-c', '--comment', nargs='+', action='store', dest='comment')

    def _has_fail(self, response):
        if isinstance(response, dict):
            # Fail
            if response.get('error'):
                self.log('error', response['error'])
                return True
            return False
        else:
            return False

    def run(self):
        super(VirusTotal, self).run()
        if self.args is None:
            return

        if not HAVE_VT:
            self.log('error', "Missing dependency, install virustotal-api (`pip install virustotal-api`)")
            return

        if self.args.hash:
            if cfg.virustotal.virustotal_has_private_key:
                response = self.vt.get_file(self.args.hash)
                if not self._has_fail(response):
                    tmp = tempfile.NamedTemporaryFile(delete=False)
                    tmp.write(response)
                    tmp.close()
                    return __sessions__.new(tmp.name)
            elif cfg.virustotal.virustotal_has_intel_key:
                tmp = tempfile.NamedTemporaryFile(delete=False)
                tmp.close()
                response = self.vt_intel.get_file(self.args.hash, tmp.name)
                if not self._has_fail(response):
                    return __sessions__.new(tmp.name)
            else:
                self.log('error', 'This command requires virustotal private ot intelligence API key')

        if not __sessions__.is_set():
            self.log('error', "No session opened")
            return

        response = self.vt.get_file_report(__sessions__.current.file.md5)
        if self._has_fail(response):
            return

        virustotal = response['results']
        rows = []
        if virustotal.get('scans'):
            for engine, signature in virustotal['scans'].items():
                if signature['detected']:
                    signature = signature['result']
                else:
                    signature = ''
                rows.append([engine, signature])

        rows.sort()
        if rows:
            self.log('info', "VirusTotal Report:")
            self.log('table', dict(header=['Antivirus', 'Signature'], rows=rows))

            if self.args.submit:
                self.log('', "")
                self.log('info', "The file is already available on VirusTotal, no need to submit")
        else:
            self.log('info', "The file does not appear to be on VirusTotal yet")

            if self.args.submit:
                response = self.vt.scan_file(__sessions__.current.file.path)
                if not self._has_fail(response):
                    virustotal = response['results']
                    if virustotal.get('verbose_msg'):
                        self.log('info', "{}: {}".format(bold("VirusTotal message"), virustotal['verbose_msg']))

        if self.args.comment:
            response = self.vt.put_comments(__sessions__.current.file.md5, ' '.join(self.args.comment))
            if not self._has_fail(response):
                virustotal = response['results']
                if virustotal.get('verbose_msg'):
                    self.log('info', ("{}: {}".format(bold("VirusTotal message"), virustotal['verbose_msg'])))
