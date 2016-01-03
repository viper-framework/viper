# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import tempfile

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

from viper.common.out import bold
from viper.common.abstracts import Module
from viper.core.session import __sessions__
from viper.core.config import Config

cfg = Config()


# TODO: All that JSON exception handling is REALLY ugly. Needs to be fixed.

class VirusTotal(Module):
    cmd = 'virustotal'
    description = 'Lookup the file on VirusTotal'
    authors = ['nex']

    def __init__(self):
        super(VirusTotal, self).__init__()
        self.parser.add_argument('-s', '--submit', action='store_true', help='Submit file to VirusTotal (by default it only looks up the hash)')
        self.parser.add_argument('-d','--download', action='store', dest='hash')
        self.parser.add_argument('-c','--comment',nargs='+', action='store', dest='comment')

    def run(self):
        super(VirusTotal, self).run()
        if self.args is None:
            return

        if self.args.hash:
            try:
                params = {'apikey': cfg.virustotal.virustotal_key,'hash':self.args.hash}
                response = requests.get(cfg.virustotal.virustotal_url_download, params=params)

                if response.status_code == 403:
                    self.log('error','This command requires virustotal private API key')
                    self.log('error','Please check that your key have the right permissions')
                    return
                if response.status_code == 200:
                    response = response.content
                    tmp = tempfile.NamedTemporaryFile(delete=False)
                    tmp.write(response)
                    tmp.close()
                    return __sessions__.new(tmp.name)

            except Exception as e:
                    self.log('error', "Failed to download file: {0}".format(e))

        if not HAVE_REQUESTS:
            self.log('error', "Missing dependency, install requests (`pip install requests`)")
            return

        if not __sessions__.is_set():
            self.log('error', "No open session")
            return

        data = {'resource': __sessions__.current.file.md5, 'apikey': cfg.virustotal.virustotal_key}

        try:
            response = requests.post(cfg.virustotal.virustotal_url, data=data)
        except Exception as e:
            self.log('error', "Failed performing request: {0}".format(e))
            return

        try:
            virustotal = response.json()
            # since python 2.7 the above line causes the Error dict object not callable
        except Exception as e:
            # workaround in case of python 2.7
            if str(e) == "'dict' object is not callable":
                try:
                    virustotal = response.json
                except Exception as e:
                    self.log('error', "Failed parsing the response: {0}".format(e))
                    self.log('error', "Data:\n{}".format(response.content))
                    return
            else:
                self.log('error', "Failed parsing the response: {0}".format(e))
                self.log('error', "Data:\n{}".format(response.content))
                return

        rows = []
        if 'scans' in virustotal:
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
                try:
                    data = {'apikey': cfg.virustotal.virustotal_key}
                    files = {'file': open(__sessions__.current.file.path, 'rb').read()}
                    response = requests.post(cfg.virustotal.virustotal_url_submit, data=data, files=files)
                except Exception as e:
                    self.log('error', "Failed Submit: {0}".format(e))
                    return

                try:
                    virustotal = response.json()
                    # since python 2.7 the above line causes the Error dict object not callable
                except Exception as e:
                    # workaround in case of python 2.7
                    if str(e) == "'dict' object is not callable":
                        try:
                            virustotal = response.json
                        except Exception as e:
                            self.log('error', "Failed parsing the response: {0}".format(e))
                            self.log('error', "Data:\n{}".format(response.content))
                            return
                    else:
                        self.log('error', "Failed parsing the response: {0}".format(e))
                        self.log('error', "Data:\n{}".format(response.content))
                        return

                if 'verbose_msg' in virustotal:
                    self.log('info', "{}: {}".format(bold("VirusTotal message"), virustotal['verbose_msg']))

        if self.args.comment:
            try:

                data = {'apikey' : cfg.virustotal.virustotal_key, 'resource': __sessions__.current.file.md5, 'comment' : ' '.join(self.args.comment)}
                response = requests.post(cfg.virustotal.virustotal_url_comment,data=data)
            except Exception as e:
                self.log('error',"Failed Submit Comment: {0}".format(e))
                return
            try:
                virustotal = response.json()
                # since python 2.7 the above line causes the Error dict object not callable
            except Exception as e:
                # workaround in case of python 2.7
                if str(e) == "'dict' object is not callable":
                    try:
                        virustotal = response.json
                    except Exception as e:
                        self.log('error',"Failed parsing the response: {0}".format(e))
                        self.log('error',"Data:\n{}".format(response.content))
                        return
                else:
                    self.log('error',"Failed parsing the response: {0}".format(e))
                    self.log('error',"Data:\n{}".format(response.content))
                    return

            if 'verbose_msg' in virustotal:
                self.log('info',("{}: {}".format(bold("VirusTotal message"), virustotal['verbose_msg'])))
                return
