# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os
import json
import getpass

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

try:
    from bs4 import BeautifulSoup
    HAVE_BS4 = True
except ImportError:
    HAVE_BS4 = False

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __sessions__

from config import MALWR_USER, MALWARE_PASS, ANUBIS_USER, ANUBIS_PASS


MALWR_LOGIN = 'https://malwr.com/account/login/'
MALWR_SEARCH = 'https://malwr.com/analysis/search/'
MALWR_PREFIX = 'https://malwr.com'

ANUBIS_LOGIN = 'https://anubis.iseclab.org/?action=login' 
ANUBIS_SEARCH = 'https://anubis.iseclab.org/?action=hashquery' 
ANUBIS_PREFIX = 'https://anubis.iseclab.org/'

class Reports(Module):
    cmd = 'reports'
    description = 'Online Sandboxes Reports'
    authors = ['emdel', 'nex']

    def authenticate(self):
        username = raw_input('Username: ')
        password = getpass.getpass('Password: ')

        return (username, password)

    def malwr_parse(self, page):
        reports = []
        soup = BeautifulSoup(page)
        tables = soup.findAll('table')
        if len(tables) > 1:
            table = tables[1]
            rows = table.findAll('tr')
            for row in rows:
                cols = row.findAll('td')
                if cols:
                    time = str(cols[0].string)
                    link = cols[1].find('a')
                    url = '{0}{1}'.format(MALWR_PREFIX, link.get("href"))
                    reports.append([time, url])

            return reports

    def malwr(self):
        if not MALWR_USER or not MALWR_PASS:
            choice = raw_input("You need to specify a valid username/password, login now? [y/N] ")
            if choice == 'y':
                username, password = self.authenticate()
            else:
                return
        else:
            username = MALWR_USER
            password = MALWR_PASS

        sess = requests.Session()
        sess.auth = (username, password)

        sess.get(MALWR_LOGIN, verify=False)
        csrf = sess.cookies['csrftoken']

        res = sess.post(
            MALWR_LOGIN,
            {'username': username, 'password': password, 'csrfmiddlewaretoken': csrf},
            headers=dict(Referer=MALWR_LOGIN),
            verify=False,
            timeout=60
        )

        payload = {'search': __sessions__.current.file.sha256, 'csrfmiddlewaretoken': csrf}
        headers = {"Referer": MALWR_SEARCH}

        p = sess.post(
            MALWR_SEARCH,
            payload,
            headers=headers,
            timeout=60,
            verify=False
        )
        
        reports = self.malwr_parse(p.text)
        if not reports:
            print_info("No reports for opened file")
            return

        print(table(header=['Time', 'URL'], rows=reports))

    def anubis_parse(self, page):
        reports = []
        soup = BeautifulSoup(page)
        tables = soup.findAll('table')

        if len(tables) >= 5:
            table = tables[4]
            cols = table.findAll('td')
            time = cols[1].string.strip()
            link = cols[4].find('a')
            url = '{0}{1}'.format(ANUBIS_PREFIX, link.get('href'))
            reports.append([time, url])
            return reports

    def anubis(self):
        if not ANUBIS_USER or not ANUBIS_PASS:
            choice = raw_input("You need to specify a valid username/password, login now? [y/N] ")
            if choice == 'y':
                username, password = self.authenticate()
            else:
                return
        else:
            username = ANUBIS_USER
            password = ANUBIS_PASS

        sess = requests.Session()
        sess.auth = (username, password)

        res = sess.post(
            ANUBIS_LOGIN,
            {'username' : username, 'password' : password},
            verify=False
        )
        res = sess.post(
            ANUBIS_SEARCH,
            {'hashlist' : __sessions__.current.file.sha256},
            verify=False
        )
        
        reports = self.anubis_parse(res.text)
        if not reports:
            print_info("No reports for opened file")
            return

        print(table(header=['Time', 'URL'], rows=reports))

    def threat(self):
        # need the URL and the date
        url = 'http://www.threatexpert.com/report.aspx?md5={0}'.format(__sessions__.current.file.md5)
        page = requests.get(url)
        reports = []
        soup = BeautifulSoup(page.text)
        if soup.title.text.startswith('ThreatExpert Report'):
            lists = soup.findAll('li')
            if len(lists) > 0:
                time = lists[1].text[21:]
                reports.append([time, url])
                print(table(header=['Time', 'URL'], rows=reports))
        else:
            print_info("No reports for opened file")
 
    def joe(self):
        url = 'http://www.joesecurity.org/reports/report-{0}.html'.format(__sessions__.current.file.md5)
        page = requests.get(url)
        if '<h2>404 - File Not Found</h2>' in page.text:
            print_info("No reports for opened file")
        else:
            print_info("Report found at {0}".format(url))
            
    def meta(self):
        url = 'https://www.metascan-online.com/en/scanresult/file/{0}'.format(__sessions__.current.file.md5)
        page = requests.get(url)
        reports = []
        print page.text
        if '<title>Error</title>' in page.text:
            print_info("No reports for opened file")
            return
        pattern = 'scanResult = (.*)};'
        match = re.search(pattern, page.text)
        raw_results = match.group(0)[13:-1]
        json_results = json.loads(raw_results)
        unprocessed =  json_results['scan_results']['scan_details']
        for vendor, results in unprocessed.iteritems():
            if results['scan_result_i'] == 1:
                reports.append([vendor, string_clean(results['threat_found']), results['def_time']])
                print(table(header=['Vendor', 'Result', 'Time'], rows=reports))
                return

    def usage(self):
        print("Usage: reports <malwr|anubis|threat|joe|meta>")

    def help(self):
        self.usage()
        print("")
        print("Options:")
        print("\thelp\tShow this help message")
        print("\tmalwr\tFind reports on Malwr")
        print("\tanubis\tFind reports on Anubis")
        print("\tthreat\tFind reports on ThreatExchange")
        print("\tjoe\tFind reports on Joe Sandbox")
        print("\tmeta\tFind reports on metascan")
        print("") 

    def run(self):
        if not HAVE_REQUESTS and not HAVE_BS4:
            print_error("Missing dependencies (`pip install requests beautifulsoup4`)")
            return

        if not __sessions__.is_set():
            print_error("No session opened")
            return

        if len(self.args) == 0:
            self.help()
            return

        if self.args[0] == 'help':
            self.help()
        elif self.args[0] == 'malwr':
            self.malwr()
        elif self.args[0] == 'anubis':
            self.anubis()
        elif self.args[0] == 'threat':
            self.threat()
        elif self.args[0] == 'joe':
            self.joe()
        elif self.args[0] == 'meta':
            self.meta()