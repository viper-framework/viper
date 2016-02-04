# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import itertools

from viper.common.abstracts import Module
from viper.core.session import __sessions__
from viper.core.database import Database


class Editdistance(Module):
    cmd = 'editdistance'
    description = 'Edit distance on the filenames'
    authors = ['emdel', 'nex']

    def __init__(self):
        super(Editdistance, self).__init__()

    def edit(self):
        db = Database()
        samples = db.find(key='all')

        filenames = []
        for sample in samples:
            if sample.sha256 == __sessions__.current.file.sha256:
                continue

            filenames.append(sample.name)

        # from http://hetland.org/coding/python/levenshtein.py
        def levenshtein(a, b):
            "Calculates the Levenshtein distance between a and b."
            n, m = len(a), len(b)
            if n > m:
                # Make sure n <= m, to use O(min(n,m)) space
                a, b = b, a
                n, m = m, n

            current = range(n + 1)
            for i in range(1, m + 1):
                previous, current = current, [i] + [0] * n
                for j in range(1, n + 1):
                    add, delete = previous[j] + 1, current[j - 1] + 1
                    change = previous[j - 1]
                    if a[j - 1] != b[i - 1]:
                        change = change + 1
                    current[j] = min(add, delete, change)

            return current[n]

        distance = []
        for i in itertools.combinations(filenames, 2):
            edit = levenshtein(i[0], i[1])
            distance.append(edit)

        self.log('info', "Average Edit distance: {0}".format(sum(distance) / len(distance)))

    def run(self):
        super(Editdistance, self).run()
        if self.args is None:
            return

        if not __sessions__.is_set():
            self.log('error', "No open session")
            return

        self.edit()
