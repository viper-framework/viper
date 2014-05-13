# Copyright (C) 2013-2014 Claudio "nex" Guarnieri.
# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os
import json
import requests

from bs4 import BeautifulSoup

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __session__

# Malwr parameters
MALWR_LOGIN = 'https://malwr.com/account/login/'
MALWR_USER = 'user'
MALWR_PASS = 'pass'
MALWR_SEARCH = 'https://malwr.com/analysis/search/'
MALWR_PREFIX = 'https://malwr.com'

# Anubis parameters
ANUBIS_LOGIN = 'https://anubis.iseclab.org/?action=login' 
ANUBIS_USER = 'user'
ANUBIS_PASS = 'pass'
ANUBIS_SEARCH = 'https://anubis.iseclab.org/?action=hashquery' 
ANUBIS_PREFIX = 'https://anubis.iseclab.org/'


class Reports(Module):
    cmd = 'reports'
    description = 'Online Sandboxes Reports'


    def usage(self):
        print("Usage: reports <sandbox> <hash>")


    def help(self):
        self.usage()
        print("")
        print("Options:")
        print("\thelp\t\tShow this help message")
        print("\tmalwr <hash>\t\tLink to Malwr report")
        print("\tanubis <hash>\t\tLink to Anubis report")
        print("") 


    def create_session(self):
        return requests.Session()


    def authentication(self, s, username, password):
        s.auth = (username, password)
        return
   

    def parsing_malwr_search_page(self, page):
        res = {}
        soup = BeautifulSoup(page)
        tables = soup.findAll("table")
        if len(tables) > 1:
            t = tables[1]
            rows = t.findAll("tr")
            for r in rows:
                cols = r.findAll("td")
                if cols:
                    time = cols[0].string
                    link = cols[1].find("a")
                    url = "%s%s" % (MALWR_PREFIX, link.get("href"))
                    res[url] = time
            return res
        return None


    def print_reports(self, reports, digest):
        print ">> %s" % digest
        for url, time in reports.items():
            print "\t -> %s - %s" % (url, time)


    def malwr(self, digest):
        # login
        s = self.create_session()
        self.authentication(s, MALWR_USER, MALWR_PASS)
        # getting csrf token
        s.get(MALWR_LOGIN, verify = False)
        csrf = s.cookies['csrftoken']
        # crafting the post request
        r = s.post(MALWR_LOGIN, {'username': MALWR_USER, 'password': MALWR_PASS,
        'csrfmiddlewaretoken': csrf}, headers = dict(Referer = MALWR_LOGIN),
        verify = False, timeout = 3)
        # search the hash
        payload = {'search': digest, 'csrfmiddlewaretoken': csrf}
        headers = {"Referer": MALWR_SEARCH}
        p = s.post(MALWR_SEARCH, payload, headers=headers, timeout=20, verify=False)
        # parsing the page 
        reports = self.parsing_malwr_search_page(p.text)
        # printing the reports
        if reports:
            self.print_reports(reports, digest)
            return
        print "No reports for %s" % digest


    def parsing_anubis_search_page(self, page):
        reports = {}
        soup = BeautifulSoup(page)
        tables = soup.findAll("table")
        if len(tables) >= 5:
            t = tables[4]
            cols = t.findAll("td")
            time = cols[1].string.strip()
            link = cols[4].find("a")
            url = "%s%s" % (ANUBIS_PREFIX, link.get("href"))
            reports[url] = time
            return reports
        return None


    def anubis(self, digest):
        # login
        s = self.create_session()
        self.authentication(s, ANUBIS_USER, ANUBIS_PASS)
        # post login
        r = s.post(ANUBIS_LOGIN, {'username' : ANUBIS_USER, 'password' : ANUBIS_PASS}, verify=False)
        # post search
        r = s.post(ANUBIS_SEARCH, {'hashlist' : digest}, verify=False)
        # parsing the page
        reports = self.parsing_anubis_search_page(r.text)
        if reports:
            self.print_reports(reports, digest)
            return
        print "No reports for %s" % digest


    def run(self):
        # TODO: scan for the current session
        #if not __session__.is_set():
        #    print_error("No session opened")
        #    return

        if len(self.args) == 0:
            self.help()
            return

        if self.args[0] == 'help':
            self.help()
        elif self.args[0] == 'malwr':
            if len(self.args) != 2: self.help() 
            self.malwr(self.args[1])
        elif self.args[0] == 'anubis':
            if len(self.args) != 2: self.help()
            self.anubis(self.args[1])
 
