# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import multiprocessing
import json
import os
import base64
from datetime import datetime
from glob import glob
from shutil import copyfile

from viper.common.abstracts import Module
from viper.core.config import Config
from viper.core.project import __project__

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

try:
    from scrapy import Spider
    from scrapy.crawler import CrawlerProcess, Crawler
    from scrapy import signals
    from scrapy_splash import SplashRequest
    HAVE_SCRAPY = True
except ImportError:
    HAVE_SCRAPY = False

try:
    from har2tree import Har2Tree
    HAVE_ETE = True
except:
    HAVE_ETE = False

cfg = Config()


if HAVE_SCRAPY:
    class CustomCrawler():
        class MySpider(Spider):
            name = 'viper'

            def __init__(self, url, *args, **kwargs):
                self.start_url = url

            def start_requests(self):
                yield SplashRequest(self.start_url, self.parse, endpoint='render.json',
                                    args={'har': 1, 'png': 1})

            def parse(self, response):
                return response.data

        def __init__(self, useragent):
            self.process = CrawlerProcess({'LOG_ENABLED': False})
            self.crawler = Crawler(self.MySpider, {
                'LOG_ENABLED': False,
                'USER_AGENT': useragent,
                'SPLASH_URL': cfg.scraper.splash_url,
                'DOWNLOADER_MIDDLEWARES': {'scrapy_splash.SplashCookiesMiddleware': 723,
                                           'scrapy_splash.SplashMiddleware': 725,
                                           'scrapy.downloadermiddlewares.httpcompression.HttpCompressionMiddleware': 810,
                                           },
                'SPIDER_MIDDLEWARES': {'scrapy_splash.SplashDeduplicateArgsMiddleware': 100},
                'DUPEFILTER_CLASS': 'scrapy_splash.SplashAwareDupeFilter',
                # 'HTTPCACHE_STORAGE': 'scrapy_splash.SplashAwareFSCacheStorage'
            })

        def crawl(self, url):
            crawled_items = []

            def add_item(item):
                crawled_items.append(item)

            self.crawler.signals.connect(add_item, signals.item_scraped)
            self.process.crawl(self.crawler, url=url)
            self.process.start()
            return crawled_items


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
        self.parser.add_argument("-l", "--list", action='store_true', help='List already scraped URLs')
        self.parser.add_argument("-i", "--id", help='Dump ID (get it from -l/--list).')
        self.parser.add_argument("-d", "--delete", action='store_true', help='Delete a report (ID, or all).')
        self.parser.add_argument("-v", "--view", action='store_true', help='View a dump.')
        self.parser.add_argument("-t", "--tree", action='store_true', help='Tree view.')
        self.parser.add_argument("-ch", "--copy_har", help='Copy harfile somewhere else.')
        self.parser.add_argument("-q", "--quiet", action='store_true', help='Quiet view (Only display external URLs)')
        self.parser.add_argument("--verbose", action='store_true', help='Verbose view')

    def crawl(self, ua, url):
        def _crawl(queue, ua, url):
            crawler = CustomCrawler(ua)
            res = crawler.crawl(url)
            queue.put(res)

        q = multiprocessing.Queue()
        p = multiprocessing.Process(target=_crawl, args=(q, ua, url))
        p.start()
        res = q.get()
        p.join()
        return res

    def scrape(self, ua, url):
        if not HAVE_SCRAPY:
            self.log('error', 'Missing dependencies: scrapy and scrapy-splash')
            return
        items = self.crawl(ua, url)
        if not items:
            self.log('error', 'Unable to crawl. Probably a network problem.')
            return None
        # For now, only one item
        item = items[0]
        now = datetime.now().isoformat()
        with open(os.path.join(self.scraper_store, '{}.json'.format(now)), 'w') as f:
            json.dump(item, f)
        png = item['png']
        with open(os.path.join(self.scraper_store, '{}.png'.format(now)), 'wb') as f:
            f.write(base64.b64decode(png))
        harfile = item['har']
        with open(os.path.join(self.scraper_store, '{}.har'.format(now)), 'w') as f:
            json.dump(harfile, f)
        return now

    def tree(self):
        if not HAVE_ETE:
            self.log('error', 'Missing dependency: git+https://github.com/viper-framework/har2tree.git')
            return
        isots = self._get_report_timestamp(self.reportid)
        if isots is None:
            return
        har = os.path.join(self.scraper_store, '{}.har'.format(isots))
        if not os.path.exists(har):
            self.log('error', 'No har file available.')
            return
        with open(har, 'r') as f:
            harfile = json.load(f)
        tree_file = os.path.join(self.scraper_store, "{}.pdf".format(isots))
        h2t = Har2Tree(harfile)
        h2t.tree(tree_file)
        self.log('success', 'Tree dump created: {}'.format(tree_file))

    def view(self):
        isots = self._get_report_timestamp(self.reportid)
        if isots is None:
            return
        json_file = os.path.join(self.scraper_store, '{}.json'.format(isots))
        with open(json_file, 'r') as f:
            loaded_json = json.load(f)
        self.log('info', 'Requested URL: {}'.format(loaded_json['requestedUrl']))
        if loaded_json['url'] != loaded_json['requestedUrl']:
            self.log('item', 'Redirected to: {}'.format(loaded_json['url']))
        if loaded_json.get('title'):
            self.log('item', loaded_json['title'])

        png = os.path.join(self.scraper_store, '{}.png'.format(isots))
        if os.path.exists(png):
            self.log('success', 'PNG view ({}): {}'.format(loaded_json['geometry'], png))
        else:
            self.log('warning', 'No PNG view available.')

        har = os.path.join(self.scraper_store, '{}.har'.format(isots))
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
        return sorted(glob(os.path.join(self.scraper_store, '*.json')))

    def _get_report_timestamp(self, reportid):
        if reportid.isdigit():
            if int(reportid) > len(self._get_reports_sorted()):
                self.log('error', 'Invalid report ID, nothing to find there.')
                return None
            reportfile = self._get_reports_sorted()[int(self.reportid) - 1]
            return os.path.basename(reportfile).strip('.json')
        else:
            # Check if there is a report available to with that timestamp
            json_file = os.path.join(self.scraper_store, '{}.json'.format(reportid))
            if not os.path.exists(json_file):
                self.log('error', 'Nothing to display.')
                return None
            return reportid

    def list(self):
        header = ['ID', 'Time', 'Requested URL']
        rows = []
        i = 1
        for json_file in self._get_reports_sorted():
            ts = os.path.basename(json_file).strip('.json')
            with open(json_file, 'r') as f:
                loaded_json = json.load(f)
            row = [i, ts, loaded_json['requestedUrl']]
            i += 1
            rows.append(row)
        self.log('table', dict(header=header, rows=rows))

    def copy_har(self, destination):
        isots = self._get_report_timestamp(self.reportid)
        if isots is None:
            return
        copyfile(os.path.join(self.scraper_store, '{}.har'.format(isots)), destination)
        self.log('success', 'Har file copied to {}.'.format(destination))

    def delete(self):
        if self.reportid == 'all':
            for path in glob(os.path.join(self.scraper_store, '*')):
                os.remove(path)
                self.log('success', '{} deleted.'.format(path))
            return
        isots = self._get_report_timestamp(self.reportid)
        if isots is None:
            return
        for path in glob(os.path.join(self.scraper_store, '{}.*'.format(isots))):
            os.remove(path)
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
            self.reportid = self.scrape(self.user_agents[0], self.args.url)
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
