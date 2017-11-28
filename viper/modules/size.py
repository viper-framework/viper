# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os

from viper.common.out import bold
from viper.common.abstracts import Module
from viper.core.session import __sessions__
from viper.core.database import Database
from viper.core.storage import get_sample_path


class SIZE(Module):
    cmd = 'size'
    description = 'Size command to show/scan/cluster files'
    authors = ['emdel']

    def __init__(self):
        super(SIZE, self).__init__()
        self.parser.add_argument('-a', '--all', action='store_true', help='Show all')
        self.parser.add_argument('-c', '--cluster', action='store_true', help='Cluster')
        self.parser.add_argument('-s', '--scan', action='store_true', help='Scan')
        self.file_size = 0

    def __check_session(self):
        if not __sessions__.is_set():
            self.log('error', "No open session")
            return False
        return True

    def size_all(self):
        db = Database()
        samples = db.find(key='all')

        rows = []
        for sample in samples:
            sample_path = get_sample_path(sample.sha256)
            if not os.path.exists(sample_path):
                continue

            try:
                cur_size = os.path.getsize(sample_path)
            except Exception as e:
                self.log('error', "Error {0} for sample {1}".format(e, sample.sha256))
                continue

            rows.append([sample.md5, sample.name, cur_size])

        self.log('table', dict(header=['MD5', 'Name', 'Size (B)'], rows=rows))

        return

    def size_cluster(self):
        db = Database()
        samples = db.find(key='all')

        cluster = {}
        for sample in samples:
            sample_path = get_sample_path(sample.sha256)
            if not os.path.exists(sample_path):
                continue

            try:
                cur_size = os.path.getsize(sample_path)
            except Exception as e:
                self.log('error', "Error {0} for sample {1}".format(e, sample.sha256))
                continue

            if cur_size not in cluster:
                cluster[cur_size] = []

            cluster[cur_size].append([sample.md5, sample.name])

        for cluster_name, cluster_members in cluster.items():
            # Skipping clusters with only one entry.
            if len(cluster_members) == 1:
                continue

            self.log('info', "Cluster size {0} with {1} elements".format(bold(cluster_name), len(cluster_members)))
            self.log('table', dict(header=['MD5', 'Name'], rows=cluster_members))

    def size_scan(self):
        db = Database()
        samples = db.find(key='all')

        rows = []
        for sample in samples:
            if sample.sha256 == __sessions__.current.file.sha256:
                continue

            sample_path = get_sample_path(sample.sha256)
            if not os.path.exists(sample_path):
                continue

            try:
                cur_size = os.path.getsize(sample_path)
            except Exception:
                continue

            if self.file_size == cur_size:
                rows.append([sample.md5, sample.name])

        if len(rows) > 0:
            self.log('info', "Following are samples with size {0}".format(bold(self.file_size)))
            self.log('table', dict(header=['MD5', 'Name'], rows=rows))

    def run(self):
        super(SIZE, self).run()
        if self.args is None:
            return

        if not self.__check_session():
            self.log('error', 'At least one of the parameters is required')
            self.usage()
            return

        self.file_size = __sessions__.current.file.size
        self.log("info", "Size: {0} B".format(self.file_size))

        if self.args.all:
            self.size_all()
        elif self.args.cluster:
            self.size_cluster()
        elif self.args.scan:
            self.size_scan()
        else:
            self.log('error', 'At least one of the parameters is required')
            self.usage()
