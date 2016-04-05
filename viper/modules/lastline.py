

lastlineKEY = "" 
lastlineTOKEN = "" 
lastlinePORTALACCOUNT = "" 

import json

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

from viper.common.abstracts import Module
from viper.core.session import __sessions__

BASE_URL = 'https://analysis.lastline.com'
SUBMIT_URL = '/analysis/submit/file'


class LastLine(Module):
    cmd = 'lastline'
    description = 'Submit files and retrieve reports from LastLine (default will print short summary) '
    authors = ['gelos']

    def __init__(self):
        super(LastLine, self).__init__()
        self.parser.add_argument('-s', '--submit', action='store_true', help='Submit file to LastLine')
        self.parser.add_argument('-r','--report', action='store_true', help='Get report from LastLine')

    def run(self):

        super(LastLine, self).run()
        if self.args is None:
            return

        if not HAVE_REQUESTS:
            self.log('error', "Missing dependency, install requests (`pip install requests`)")
            return

        if not __sessions__.is_set():
            self.log('error', "No open session")
            return

        if self.args.submit:
            try:
                file = {'file' : open(__sessions__.current.file.path, 'rb').read()}
                data = {'key':lastlineKEY, 'api_token':lastlineTOKEN,'push_to_portal_account':lastlinePORTALACCOUNT}
                response = requests.post(BASE_URL+SUBMIT_URL,data=data,files=file)
                response = response.json()

                if response['success'] == 0:
                    self.log('error',response['error'])
                    return
                if response['success'] == 1:
                    self.log('info','Successfully submitted file to LastLine, task UUID: '+response['data']['task_uuid'])
                    return


            except Exception as e:
                self.log('error', "Failed performing request: {0}".format(e))
                return

        try:

            data = {'key':lastlineKEY, 'api_token':lastlineTOKEN,'md5':__sessions__.current.file.md5,'push_to_portal_account':lastlinePORTALACCOUNT}
            response = requests.post(BASE_URL+SUBMIT_URL,data=data)
            response = response.json()
            if response['success'] == 0:
                self.log('error',response['error'])
                return
            if response['success'] == 1:
                self.log('info', "LastLine Report:")
                if self.args.report:
                    self.log('',json.dumps(response,indent=4,sort_keys=False))
                    return

                #file malicious scoring
                if 'score' in response['data']:
                    self.log('info','Malicious score: '+str(response['data']['score']))
                if 'submission' in response['data']:
                    self.log('info','Submission date: '+str(response['data']['submission']))
                #generating malicous activity list
                if 'malicious_activity' in response['data']:
                    malicous_activity = []
                    i = 0
                    while(i < len(response['data']['malicious_activity'])):
                        malicous_activity.append([i,response['data']['malicious_activity'][i]])
                        i += 1
                    self.log('table', dict(header=['id', 'Malicious Activity'], rows=malicous_activity))

                #generating url_summary list
                if 'url_summary' in response['data']['report']:
                    url_summary = []
                    i = 0
                    while (i < len(response['data']['report']['url_summary'])):
                        url_summary.append([i,response['data']['report']['url_summary'][i]])
                        i += 1
                    self.log('table', dict(header=['id', 'URL Found'], rows=url_summary))
            return
        except Exception as e:
            self.log('error', "Failed performing request: {0}".format(e))



