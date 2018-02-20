# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import json
import os
import base64
from datetime import datetime
from glob import glob
from shutil import copy2

from viper.common.abstracts import Module
from viper.core.config import __config__
from viper.core.project import __project__
import logging

logger = logging.getLogger(__name__)


try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

try:
    from scrapysplashwrapper import crawl
    HAVE_SCRAPY = True
except ImportError:
    HAVE_SCRAPY = False

try:
    from har2tree import CrawledTree
    HAVE_ETE = True
except ImportError:
    HAVE_ETE = False

cfg = __config__


class Scraper(Module):
    cmd = 'scraper'
    description = 'Scrap a webside using scrapy and splash. Requires a running splash instance, provided as a docker thingie.'
    authors = ['Raphaël Vinot']

    def __init__(self):
        super(Scraper, self).__init__()
        try:
            self.user_agents = cfg.useragents.ua.split('\n')
        except Exception:
            # Use a generic user agent in case the viper user didn't update their config file
            self.user_agents = ['Mozilla/5.0 (Windows NT 6.3; WOW64; rv:53.0) Gecko/20100101 Firefox/53.0']
        self.scraper_store = os.path.join(__project__.get_path(), 'scraper')
        if not os.path.exists(self.scraper_store):
            os.makedirs(self.scraper_store)
        self.quiet = False
        self.very_quiet = False
        self.verbose = False
        self.debug = False
        # Scraping paramaters
        self.parser.add_argument("-u", "--url", help='URL to scrap')
        self.parser.add_argument("--depth", type=int, default=1, help='Depth to crawl on the website')

        # Actions on already scraped data
        self.parser.add_argument("-l", "--list", action='store_true', help='List already scraped URLs')

        group1 = self.parser.add_argument_group('ID details', 'Actions on scraped data (by ID).')
        group1.add_argument("-i", "--id", type=int, help='Dump ID (get it from -l/--list).')
        group1.add_argument("-d", "--delete", action='store_true', help='Delete a report (ID, or all).')
        group1.add_argument("-v", "--view", action='store_true', help='View a dump.')
        group1.add_argument("-t", "--tree", action='store_true', help='Tree view.')
        group1.add_argument("-ch", "--copy_har", help='Copy harfiles somewhere else.')

        # General parameters
        self.parser.add_argument("-vq", "--very_quiet", action='store_true', help='Very quiet view (Only display hostnames)')
        self.parser.add_argument("-q", "--quiet", action='store_true', help='Quiet view (Only display external URLs)')
        self.parser.add_argument("--verbose", action='store_true', help='Verbose view')
        self.parser.add_argument("--debug", action='store_true', help='Enable debug on the crawler.')

    def scrape(self, ua, url, depth):
        if not HAVE_SCRAPY:
            self.log('error', 'Missing dependencies: scrapy and scrapy-splash')
            return
        if self.debug:
            params = {'log_enabled': True, 'log_level': 'INFO'}
        else:
            params = {}
        items = crawl(cfg.scraper.splash_url, url, depth, ua, **params)
        width = len(str(len(items)))
        if not items:
            self.log('error', 'Unable to crawl. Probably a network problem (try --debug).')
            return None
        i = 1
        now = datetime.now().isoformat()
        dirpath = os.path.join(self.scraper_store, now)
        os.makedirs(dirpath)
        for item in items:
            with open(os.path.join(dirpath, '{0:0{width}}.json'.format(i, width=width)), 'w') as f:
                json.dump(item, f)
            png = item['png']
            with open(os.path.join(dirpath, '{0:0{width}}.png'.format(i, width=width)), 'wb') as f:
                f.write(base64.b64decode(png))
            harfile = item['har']
            with open(os.path.join(dirpath, '{0:0{width}}.har'.format(i, width=width)), 'w') as f:
                json.dump(harfile, f)
            htmlfile = item['html']
            with open(os.path.join(dirpath, '{0:0{width}}.html'.format(i, width=width)), 'w') as f:
                json.dump(htmlfile, f)
            i += 1
        return now

    def tree(self):
        if not HAVE_ETE:
            self.log('error', 'Missing dependency: git+https://github.com/viper-framework/har2tree.git')
            return
        har_files = self.all_reports[self.reportid]['har']
        ct = CrawledTree(har_files)
        ct.find_parents()
        ct.join_trees()
        tree_file = os.path.join(self.scraper_store, self.all_reports[self.reportid]['isots'], "tree.pdf")
        ct.dump_test(tree_file)
        self.log('success', 'Tree dump created: {}'.format(tree_file))

    def view(self):
        all_hostnames = set()
        for json_f, har, png in zip(self.all_reports[self.reportid]['json'],
                                    self.all_reports[self.reportid]['har'],
                                    self.all_reports[self.reportid]['png']):
            with open(json_f, 'r') as f:
                loaded_json = json.load(f)
            if not self.very_quiet:
                self.log('info', 'Requested URL: {}'.format(loaded_json['requestedUrl']))
                if loaded_json['url'] != loaded_json['requestedUrl']:
                    self.log('item', 'Redirected to: {}'.format(loaded_json['url']))
                if loaded_json.get('title'):
                    self.log('item', loaded_json['title'])

                self.log('success', 'PNG view ({}): {}'.format(loaded_json['geometry'], png))

            with open(har, 'r') as f:
                harfile = json.load(f)

            requested_domain = '.'.join(urlparse(loaded_json['url']).hostname.split('.')[-2:])
            for entry in harfile['log']['entries']:
                # Inspired by: https://github.com/fboender/harview/blob/master/src/harview.py
                if self.quiet and not entry['response']['redirectURL']:
                    url_parsed = urlparse(entry['response']['url'])
                    if url_parsed.hostname and url_parsed.hostname.endswith(requested_domain):
                        continue

                hostname = urlparse(entry['request']['url']).hostname
                if hostname:
                    all_hostnames.add(urlparse(entry['request']['url']).hostname)

                if self.very_quiet:
                    continue

                status = entry['response']['status']
                if status >= 400:
                    log_type = 'error'
                elif status >= 300:
                    log_type = 'warning'
                else:
                    log_type = 'success'

                self.log(log_type, '{} {} {}'.format(status, entry['request']['method'], entry['request']['url']))
                if 300 <= status <= 399:
                    # Redirect
                    self.log(log_type, 'Redirect to: {}'.format(entry['response']['redirectURL']))
                if not self.verbose:
                    continue
                self.log('info', 'Request headers')
                for header in entry['request']['headers']:
                    self.log('item', '{}: {}'.format(header['name'], header['value']))

                if entry['request']['method'] == 'POST' and entry['request'].get('postData'):
                    self.log('info', 'POST data ({})'.format(entry['request']['postData']['mimeType']))
                    self.log('item', entry['request']['postData']['text'])

                self.log('info', 'Response headers (status = {})'.format(entry['response']['status']))
                for header in entry['response']['headers']:
                    self.log('item', '{}: {}'.format(header['name'], header['value']))

                if 'text' in entry['response']['content']:
                    self.log('info', 'Response data ({})'.format(entry['response']['content']['mimeType']))
                    self.log('item', entry['response']['content']['text'])
        if self.very_quiet:
            self.log('info', 'All unique hostnames appearing in this trace:')
            for d in sorted(all_hostnames):
                self.log('item', d)

    def load_reports(self):
        to_return = []
        for report in self.sorted_reports():
            r = {}
            r['isots'] = report
            r['json'] = sorted(glob(os.path.join(self.scraper_store, report, '*.json')))
            r['har'] = sorted(glob(os.path.join(self.scraper_store, report, '*.har')))
            r['png'] = sorted(glob(os.path.join(self.scraper_store, report, '*.png')))
            to_return.append(r)
        return to_return

    def sorted_reports(self):
        return sorted(os.listdir(self.scraper_store))

    def list(self):
        header = ['ID', 'Time', 'Requested URL']
        rows = []
        if self.reportid is not None:
            json_files = self.all_reports[self.reportid]['json']
            for jf in json_files:
                with open(jf, 'r') as f:
                    loaded_json = json.load(f)
                row = [self.reportid + 1, self.all_reports[self.reportid]['isots'], loaded_json['requestedUrl']]
                rows.append(row)
        else:
            i = 1
            for report in self.all_reports:
                with open(report['json'][0], 'r') as f:
                    loaded_json = json.load(f)
                # print(loaded_json['requestedUrl'])
                row = [i, report['isots'], loaded_json['requestedUrl']]
                i += 1
                rows.append(row)
        self.log('table', dict(header=header, rows=rows))

    def copy_har(self, destination):
        report = self.all_reports[self.reportid]
        if os.path.exists(destination):
            if not os.path.isdir(destination):
                self.log('error', 'If it exists, destination has to be a directory.')
            else:
                destination = os.path.join(destination, report['isots'])
        os.makedirs(destination)

        for harfile in report['har']:
            copy2(harfile, destination)
        self.log('success', 'Har files copied to {}.'.format(destination))

    def delete(self):
        if self.reportid == 'all':
            for path in glob(os.path.join(self.scraper_store, '*')):
                os.rmdir(path)
                self.log('success', '{} deleted.'.format(path))
            return
        path = os.path.join(self.scraper_store, self.all_reports[self.reportid]['isots'])
        os.rmdir(path)
        self.log('success', '{} deleted.'.format(path))

    def run(self):
        super(Scraper, self).run()
        self.all_reports = self.load_reports()
        if self.args is None:
            return

        if self.args.quiet:
            self.quiet = True
        if self.args.verbose:
            self.verbose = True
        if self.args.debug:
            self.debug = True
        if self.args.very_quiet:
            self.very_quiet = True
        if self.args.id is not None:
            self.reportid = self.args.id - 1
        else:
            self.reportid = None

        if self.args.url:
            self.reportid = self.scrape(self.user_agents[0], self.args.url, self.args.depth)
            if self.reportid is None:
                return
            self.all_reports = self.load_reports()
            self.reportid = len(self.all_reports) - 1
            self.view()
        elif self.args.list:
            self.list()
        elif self.reportid:
            if self.args.view:
                self.view()
            if self.args.delete:
                self.delete()
            elif self.args.tree:
                self.tree()
            elif self.args.copy_har:
                self.copy_har(self.args.copy_har)
        else:
            return
