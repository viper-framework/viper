# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.



try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

from viper.common.abstracts import Module
from viper.core.session import __sessions__
import json

USER = None
KEY = None


class HybridAnalysis(Module):
    cmd = 'hybridanalysis'
    description = 'Submit the file to hybrid-analysis Sandbox'
    authors = ['GelosSnake']

    def __init__(self):
        super(HybridAnalysis, self).__init__()
        self.parser.add_argument('-s', '--submit', action='store_true', help='Submit file to hybrid-analysis')
        self.parser.add_argument('-r','--report', action='store_true', help='print analysis report in json format')
        self.parser.add_argument('-st','--status',action='store_true',help='Get analysis status, if finish print report URL')


    def run(self):
        super(HybridAnalysis, self).run()
        if self.args is None:
            return

        if not __sessions__.is_set():
            self.log('error', "No session opened")
            return

        if self.args.submit:
                    try:
                        url = "https://www.hybrid-analysis.com:443/api/submit"
                        data = {"key":KEY,"user":USER}
                        file = {'file': open(__sessions__.current.file.path, 'rb').read()}
                        response = requests.post(url,data=data,files=file)
                    except Exception as e:
                        self.log('error', "Failed Submit: {0}".format(e))
                        return
                    if response.status_code == 200:
                        self.log('info', 'Sample successfully submitted with id: {0}'.format(response.text))
                    else:
                        print self.log('error', 'Failed Submit: {0}'.format(response.status_code))


        if self.args.status:

            try:
                params = {"key":KEY,"user":USER}
                url = "https://hybrid-analysis.com/api/state/{0}".format(__sessions__.current.file.sha256)
                response  = requests.get(url,params=params)
                self.log('info', "analysis status: {0}".format(response.text))
                if response.text == "SUCCESS":
                    self.log('info', "report can be found on https://www.hybrid-analysis.com/sample/{0}".format(__sessions__.current.file.sha256))
            except Exception, e:
                self.log('error',"status check failed: {0}".format(e))


        if self.args.report:

            try:
                url = "https://hybrid-analysis.com/api/result/{0}".format(__sessions__.current.file.sha256)
                params = {"key":KEY,"user":USER,"type":"json"}
                response  = requests.get(url,params=params)
                response = response.json()
                self.log('info',json.dumps(response,indent=4))
            except Exception, e:
                self.log('error', "Failed to get report: {0}".format(e))




