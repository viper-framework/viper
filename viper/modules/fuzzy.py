# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import collections

from viper.common.out import bold
from viper.common.abstracts import Module
from viper.core.database import Database
from viper.core.session import __sessions__

try:
    import pydeep
    HAVE_PYDEEP = True
except ImportError:
    HAVE_PYDEEP = False


class Fuzzy(Module):
    cmd = 'fuzzy'
    description = "Search for similar files through fuzzy hashing"
    authors = ['nex', 'deralexxx']

    def __init__(self):
        super(Fuzzy, self).__init__()
        self.parser.add_argument('-v', '--verbose', action='store_true', help="Prints verbose logging")
        self.parser.add_argument('-c', '--cluster', action='store_true', help="Cluster all available samples by ssdeep")  # noqa

    def _get_ssdeep_bytes(self, ssdeep):
        # In an older database, you may endup with some hashes in binary form...
        if isinstance(ssdeep, bytes):
            # TODO: update database
            return ssdeep
        return ssdeep.encode('utf-8')

    def run(self):
        super(Fuzzy, self).run()

        if not HAVE_PYDEEP:
            self.log('error', "Missing dependency, install pydeep (`pip install pydeep`)")
            return

        arg_verbose = False
        arg_cluster = False
        if self.args:
            if self.args.verbose:
                arg_verbose = self.args.verbose
            if self.args.cluster:
                arg_cluster = self.args.cluster

            db = Database()
            samples = db.find(key='all')

            # Check if we're operating in cluster mode, otherwise we run on the
            # currently opened file.
            if arg_cluster:
                self.log('info', "Generating clusters, this might take a while...")

                clusters = dict()
                for sample in samples:
                    if not sample.ssdeep:
                        continue

                    if arg_verbose:
                        self.log('info', "Testing file {0} with ssdeep {1}".format(sample.md5, sample.ssdeep))

                    clustered = False
                    for cluster_name, cluster_members in clusters.items():
                        # Check if sample is already in the cluster.
                        if sample.md5 in cluster_members:
                            continue

                        if arg_verbose:
                            self.log('info', "Testing {0} in cluster {1}".format(sample.md5, cluster_name))

                        for member in cluster_members:
                            if sample.md5 == member[0]:
                                continue

                            member_hash = member[0]

                            member_ssdeep = db.find(key='md5', value=member_hash)[0].ssdeep
                            if pydeep.compare(self._get_ssdeep_bytes(sample.ssdeep),
                                              self._get_ssdeep_bytes(member_ssdeep)) > 40:
                                if arg_verbose:
                                    self.log('info', "Found home for {0} in cluster {1}".format(sample.md5, cluster_name))

                                clusters[cluster_name].append([sample.md5, sample.name])
                                clustered = True
                                break

                    if not clustered:
                        cluster_id = len(clusters) + 1
                        clusters[cluster_id] = [[sample.md5, sample.name], ]

                ordered_clusters = collections.OrderedDict(sorted(clusters.items()))

                self.log('info', "Following are the identified clusters with more than one member")

                for cluster_name, cluster_members in ordered_clusters.items():
                    # We include in the results only clusters with more than just
                    # one member.
                    if len(cluster_members) <= 1:
                        continue

                    self.log('info', "Ssdeep cluster {0}".format(bold(cluster_name)))
                    self.log('table', dict(header=['MD5', 'Name'], rows=cluster_members))

            # We're running against the already opened file.
            else:
                if not __sessions__.is_set():
                    self.log('error', "No open session")
                    return

                if not __sessions__.current.file.ssdeep:
                    self.log('error', "No ssdeep hash available for opened file")
                    return

                matches = []
                for sample in samples:
                    if sample.sha256 == __sessions__.current.file.sha256:
                        continue

                    if not sample.ssdeep:
                        continue

                    score = pydeep.compare(self._get_ssdeep_bytes(__sessions__.current.file.ssdeep),
                                           self._get_ssdeep_bytes(sample.ssdeep))

                    if score > 40:
                        matches.append(['{0}%'.format(score), sample.name, sample.sha256])

                    if arg_verbose:
                        self.log('info', "Match {0}%: {2} [{1}]".format(score, sample.name, sample.sha256))

                self.log('info', "{0} relevant matches found".format(bold(len(matches))))

                if len(matches) > 0:
                    self.log('table', dict(header=['Score', 'Name', 'SHA256'], rows=matches))
