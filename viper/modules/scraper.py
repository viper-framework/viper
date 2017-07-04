# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import multiprocessing
import json
import os
import base64
from datetime import datetime
from glob import glob
from shutil import copy2

from viper.common.abstracts import Module
from viper.core.config import Config
from viper.core.project import __project__
import logging

logger = logging.getLogger(__name__)


try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

try:
    from .scrap import CustomCrawler
    HAVE_SCRAPY = True
except ImportError:
    HAVE_SCRAPY = False

try:
    from har2tree import Har2Tree
    HAVE_ETE = True
except:
    HAVE_ETE = False

cfg = Config()


class Scraper(Module):
    cmd = 'scraper'
    description = 'Scrap a webside using scrapy and splash. Requires a running splash instance, provided as a docker thingie.'
    authors = ['Raphaël Vinot']

    def __init__(self):
        super(Scraper, self).__init__()
        try:
            self.user_agents = cfg.useragents.ua.split('\n')
        except:
            # Use a generic user agent in case the viper user didn't update their config file
            self.user_agents = ['Mozilla/5.0 (Windows NT 6.3; WOW64; rv:53.0) Gecko/20100101 Firefox/53.0']
        self.scraper_store = os.path.join(__project__.get_path(), 'scraper')
        if not os.path.exists(self.scraper_store):
            os.makedirs(self.scraper_store)
        self.quiet = False
        self.verbose = False
        self.parser.add_argument("-u", "--url", help='URL to scrap')
        self.parser.add_argument("--depth", type=int, default=1, help='Depth to crawl on the website')

        self.parser.add_argument("-l", "--list", action='store_true', help='List already scraped URLs')

        self.parser.add_argument("-i", "--id", help='Dump ID (get it from -l/--list).')
        self.parser.add_argument("-ld", "--list_depth", action='store_true', help='List all the urls fetched from one URL')
        self.parser.add_argument("-d", "--delete", action='store_true', help='Delete a report (ID, or all).')
        self.parser.add_argument("-v", "--view", action='store_true', help='View a dump.')
        self.parser.add_argument("-t", "--tree", action='store_true', help='Tree view.')
        self.parser.add_argument("-ch", "--copy_har", help='Copy harfiles somewhere else.')

        self.parser.add_argument("-vq", "--very_quiet", action='store_true', help='Very quiet view (Only display hostnames)')
        self.parser.add_argument("-q", "--quiet", action='store_true', help='Quiet view (Only display external URLs)')
        self.parser.add_argument("--verbose", action='store_true', help='Verbose view')

    def crawl(self, ua, url, depth):
        # scrapy-splash requires to run in its own process because twisted wants to start on a clean state for each run
        def _crawl(queue, ua, url, depth):
            crawler = CustomCrawler(ua, depth)
            res = crawler.crawl(url)
            queue.put(res)

        q = multiprocessing.Queue()
        p = multiprocessing.Process(target=_crawl, args=(q, ua, url, depth))
        p.start()
        res = q.get()
        p.join()
        return res

    def scrape(self, ua, url, depth):
        if not HAVE_SCRAPY:
            self.log('error', 'Missing dependencies: scrapy and scrapy-splash')
            return
        items = self.crawl(ua, url, depth)
        if not items:
            self.log('error', 'Unable to crawl. Probably a network problem.')
            return None
        i = 1
        now = datetime.now().isoformat()
        dirpath = os.path.join(self.scraper_store, now)
        os.makedirs(dirpath)
        for item in items:
            with open(os.path.join(dirpath, '{}.json'.format(i)), 'w') as f:
                json.dump(item, f)
            png = item['png']
            with open(os.path.join(dirpath, '{}.png'.format(i)), 'wb') as f:
                f.write(base64.b64decode(png))
            harfile = item['har']
            with open(os.path.join(dirpath, '{}.har'.format(i)), 'w') as f:
                json.dump(harfile, f)
            i += 1
        return now

    def tree(self):
        # FIXME: only display the first scraped URL
        if not HAVE_ETE:
            self.log('error', 'Missing dependency: git+https://github.com/viper-framework/har2tree.git')
            return
        isots = self._get_report_timestamp(self.reportid)
        if isots is None:
            return
        har = os.path.join(self.scraper_store, isots, '1.har')
        if not os.path.exists(har):
            self.log('error', 'No har file available.')
            return
        with open(har, 'r') as f:
            harfile = json.load(f)
        tree_file = os.path.join(self.scraper_store, isots, "1.pdf")
        h2t = Har2Tree(harfile)
        h2t.make_tree()
        h2t.render_tree_to_file(tree_file)
        self.log('success', 'Tree dump created: {}'.format(tree_file))

    def view(self):
        # FIXME: only display the first scraped URL
        isots = self._get_report_timestamp(self.reportid)
        if isots is None:
            return
        json_file = os.path.join(self.scraper_store, isots, '1.json')
        with open(json_file, 'r') as f:
            loaded_json = json.load(f)
        self.log('info', 'Requested URL: {}'.format(loaded_json['requestedUrl']))
        if loaded_json['url'] != loaded_json['requestedUrl']:
            self.log('item', 'Redirected to: {}'.format(loaded_json['url']))
        if loaded_json.get('title'):
            self.log('item', loaded_json['title'])

        png = os.path.join(self.scraper_store, isots, '1.png')
        if os.path.exists(png):
            self.log('success', 'PNG view ({}): {}'.format(loaded_json['geometry'], png))
        else:
            self.log('warning', 'No PNG view available.')

        har = os.path.join(self.scraper_store, isots, '1.har')
        if not os.path.exists(har):
            self.log('error', 'No har file available.')
            return
        with open(har, 'r') as f:
            harfile = json.load(f)

        requested_domain = '.'.join(urlparse(loaded_json['url']).hostname.split('.')[-2:])

        for entry in harfile['log']['entries']:
            # Inspired by: https://github.com/fboender/harview/blob/master/src/harview.py
            if self.quiet and not entry['response']['redirectURL']:
                url_parsed = urlparse(entry['response']['url'])
                if url_parsed.hostname and url_parsed.hostname.endswith(requested_domain):
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

    def _get_reports_sorted(self):
        return sorted(os.listdir(self.scraper_store))

    def _get_report_timestamp(self, reportid):
        if reportid.isdigit():
            if int(reportid) > len(self._get_reports_sorted()):
                self.log('error', 'Invalid report ID.')
                return None
            reportfile = self._get_reports_sorted()[int(self.reportid) - 1]
            return reportfile
        else:
            # Check if there is a report available to with that timestamp
            json_file = os.path.join(self.scraper_store, reportid, '1.json')
            if not os.path.exists(json_file):
                self.log('error', 'Nothing to display.')
                return None
            return reportid

    def list(self):
        header = ['ID', 'Time', 'Requested URL']
        rows = []
        i = 1
        for report_dir in self._get_reports_sorted():
            with open(os.path.join(self.scraper_store, report_dir, '1.json'), 'r') as f:
                loaded_json = json.load(f)
            row = [i, report_dir, loaded_json['requestedUrl']]
            i += 1
            rows.append(row)
        self.log('table', dict(header=header, rows=rows))

    def copy_har(self, destination):
        isots = self._get_report_timestamp(self.reportid)
        if isots is None:
            return
        if os.path.exists(destination):
            if not os.path.isdir(destination):
                self.log('error', 'If it exists, destination has to be a directory.')
            else:
                destination = os.path.join(destination, isots)
        os.makedirs(destination)

        for harfile in glob(os.path.join(self.scraper_store, isots, '*.har')):
            copy2(harfile, destination)
        self.log('success', 'Har files copied to {}.'.format(destination))

    def delete(self):
        if self.reportid == 'all':
            for path in glob(os.path.join(self.scraper_store, '*')):
                os.rmdir(path)
                self.log('success', '{} deleted.'.format(path))
            return
        isots = self._get_report_timestamp(self.reportid)
        if isots is None:
            return
        for path in glob(os.path.join(self.scraper_store, isots)):
            os.rmdir(path)
            self.log('success', '{} deleted.'.format(path))

    def run(self):
        super(Scraper, self).run()
        if self.args is None:
            return

        if self.args.quiet:
            self.quiet = True
        if self.args.verbose:
            self.verbose = True
        if self.args.id is not None:
            self.reportid = self.args.id

        if self.args.url:
            self.reportid = self.scrape(self.user_agents[0], self.args.url, self.args.depth)
            if self.reportid is None:
                return
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
