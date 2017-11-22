# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# and developed by Koodous Team.
# See the file 'LICENSE' for copying permission.

try:
    import requests

    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

from io import BytesIO
import logging
import hashlib
import tempfile

from viper.common.abstracts import Module
from viper.core.session import __sessions__
from viper.core.config import __config__

log = logging.getLogger('viper')

cfg = __config__
cfg.parse_http_client(cfg.koodous)
# Call: requests.get(url, proxies=cfg.koodous.proxies, verify=cfg.koodous.verify, cert=cfg.koodous.cert)


class Koodous(Module):
    cmd = 'koodous'
    description = 'Interact with Koodous'
    authors = ['asanchez@koodous.com']

    def __init__(self):
        super(Koodous, self).__init__()
        self.parser.add_argument('-d', '--download', action='store',
                                 dest='sha256')
        self.parser.add_argument('-u', '--upload', action='store_true',
                                 help='Upload file to Koodous')
        self.parser.add_argument('-c', '--comment', nargs='+', action='store',
                                 dest='comment',
                                 help='Make a comment about sample')
        self.parser.add_argument('-lc', '--load-comments', action='store_true',
                                 help='Show comments about the sample loaded')

    def run(self):
        super(Koodous, self).run()
        if self.args is None:
            return

        if not HAVE_REQUESTS:
            self.log('error', "Missing dependency, install requests (`pip install requests`)")
            return

        if self.args.sha256:
            self._download(self.args.sha256)
            return

        if self.args.upload:
            self._upload()
            return

        if self.args.comment:
            self._comment(' '.join(self.args.comment))
            return

        if self.args.load_comments:
            self._show_comments()
            return

        # If no action, show the help
        self.help()

    def _download(self, sha256):
        """
            Function to download a sample from Koodous
        """
        url = '%s/%s/download' % (cfg.koodous.base_url, sha256)

        headers = {'Authorization': 'Token %s' % cfg.koodous.token}

        response = requests.get(url=url, headers=headers, proxies=cfg.koodous.proxies,
                                verify=cfg.koodous.verify, cert=cfg.koodous.cert)
        if response.status_code == 200:
            down_url = response.json().get('download_url', None)
            response = requests.get(url=down_url, proxies=cfg.koodous.proxies,
                                    verify=cfg.koodous.verify, cert=cfg.koodous.cert)

            sha256_downloaded = hashlib.sha256(response.content).hexdigest()
            if sha256_downloaded != sha256:
                self.log('error', 'Problem downloading')
            tmp = tempfile.NamedTemporaryFile(delete=False)
            tmp.write(response.content)
            tmp.close()
            return __sessions__.new(tmp.name)

    def _upload(self):
        """
            Function to upload the session file to Koodous
        """

        content_file = __sessions__.current.file.data
        if content_file[:2] != b'PK':
            self.log('info', 'Koodous only accepts APKs, try with VirusTotal.')
            return
        sha256 = hashlib.sha256(content_file).hexdigest()

        url = '%s/%s/get_upload_url' % (cfg.koodous.base_url, sha256)
        headers = {"Authorization": "Token %s" % cfg.koodous.token}

        try:
            response = requests.get(url=url, headers=headers, proxies=cfg.koodous.proxies,
                                    verify=cfg.koodous.verify, cert=cfg.koodous.cert)

            if response.status_code == 200:
                upload_url = response.json().get('upload_url', None)
                files = {'file': BytesIO(__sessions__.current.file.data)}
                response = requests.post(url=upload_url, files=files, proxies=cfg.koodous.proxies,
                                         verify=cfg.koodous.verify, cert=cfg.koodous.cert)

                if response == 200:
                    self.log("File uploaded correctly.")
                    return
            elif response.status_code == 409:
                self.log('info', 'This file already exists in Koodous.')
            else:
                self.log('error', 'Unknown error, sorry!')
                log.error("Unknown error, sorry! Response: \n{}".format(response.status_code))

        except Exception as err:
            self.log('error', 'Network problem, please try again.')
            log.error("Network problem, please try again: \n{}".format(err))

    def _comment(self, comment):
        """
            Function to comment an APK in Koodous
        """
        headers = {"Authorization": "Token %s" % cfg.koodous.token}

        try:
            content_file = __sessions__.current.file.data
            sha256 = hashlib.sha256(content_file).hexdigest()
        except Exception:
            self.log('error', 'You have no file loaded')

        try:
            url = '%s/%s/comments' % (cfg.koodous.base_url, sha256)
            data = {'text': comment}
            response = requests.post(url=url, headers=headers, data=data,
                                     proxies=cfg.koodous.proxies, verify=cfg.koodous.verify, cert=cfg.koodous.cert)

            if response.status_code == 201:
                self.log('info', 'Comment made successfully.')
            else:
                self.log('error', 'Some problem saving the comment, please try again.')
        except Exception as err:
            self.log('error', 'Network problem, please try again.')
            log.error("Network problem, please try again: \n{}".format(err))

    def _show_comments(self):
        """
            Function to view comments of a sample in Koodous
        """
        headers = {"Authorization": "Token %s" % cfg.koodous.token}

        try:
            content_file = __sessions__.current.file.data
            sha256 = hashlib.sha256(content_file).hexdigest()
        except Exception:
            self.log('error', 'You have no file loaded')
            return
        try:
            url = '%s/%s/comments' % (cfg.koodous.base_url, sha256)
            response = requests.get(url=url, headers=headers, proxies=cfg.koodous.proxies,
                                    verify=cfg.koodous.verify, cert=cfg.koodous.cert)

            if response.json().get('count') == 0:
                self.log('info', 'This sample has no comments.')
                return
            for result in response.json().get('results'):
                self.log('info', "[{}]: {}".format(result['author']['username'], result['text']))
        except Exception as err:
            self.log('error', 'Network problem, please try again.')
            log.error("Network problem, please try again: \n{}".format(err))
