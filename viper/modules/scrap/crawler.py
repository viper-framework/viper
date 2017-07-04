# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from viper.core.config import Config
import logging

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

from scrapy import Spider
from scrapy.linkextractors import LinkExtractor
from scrapy.crawler import CrawlerProcess, Crawler
from scrapy import signals
from scrapy_splash import SplashRequest

logger = logging.getLogger(__name__)

cfg = Config()


class CustomCrawler():

    class MySpider(Spider):
        name = 'viper'

        def __init__(self, url, *args, **kwargs):
            self.start_url = url
            self.allowed_domains = ['.'.join(urlparse(url).hostname.split('.')[-2:])]

        def start_requests(self):
            yield SplashRequest(self.start_url, self.parse, endpoint='render.json',
                                args={'har': 1, 'png': 1, 'html': 1})

        def parse(self, response):
            le = LinkExtractor(allow_domains=self.allowed_domains)
            for link in le.extract_links(response):
                yield SplashRequest(link.url, self.parse, endpoint='render.json',
                                    args={'har': 1, 'png': 1, 'html': 1})
            yield response.data

    def __init__(self, useragent, depth=1):
        self.depth = depth
        self.process = CrawlerProcess({'LOG_ENABLED': False})
        self.crawler = Crawler(self.MySpider, {
            'LOG_ENABLED': False,
            'LOG_LEVEL': 'WARNING',
            'USER_AGENT': useragent,
            'SPLASH_URL': cfg.scraper.splash_url,
            'DOWNLOADER_MIDDLEWARES': {'scrapy_splash.SplashCookiesMiddleware': 723,
                                       'scrapy_splash.SplashMiddleware': 725,
                                       'scrapy.downloadermiddlewares.httpcompression.HttpCompressionMiddleware': 810,
                                       },
            'SPIDER_MIDDLEWARES': {'scrapy_splash.SplashDeduplicateArgsMiddleware': 100,
                                   'viper.modules.scrap.middleware.CustomSplashRequestDepthMiddleware': 110},
            'DUPEFILTER_CLASS': 'scrapy_splash.SplashAwareDupeFilter',
            'DEPTH_LIMIT': self.depth
            # 'HTTPCACHE_STORAGE': 'scrapy_splash.SplashAwareFSCacheStorage'
        })

    def crawl(self, url):
        crawled_items = []

        def add_item(item):
            crawled_items.append(item)

        self.crawler.signals.connect(add_item, signals.item_scraped)
        self.process.crawl(self.crawler, url=url, depth=self.depth)
        self.process.start()
        return crawled_items
