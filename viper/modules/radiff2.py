# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from viper.common.abstracts import Module
from viper.core.session import __sessions__
from viper.core.database import Database
import viper.core.storage as st

import csv
import os
import re
from subprocess import Popen, PIPE


regex_match = r'(?P<sym_1>^\S+)\s+(?P<len_1>\S+)\s+(?P<off_1>\S+)\s+\|\s+(?P<state>\S+)\s+\((?P<weight>\S+)\)\s+\|\s+(?P<off_2>\S+)\s+(?P<len_2>\S+)\s+(?P<sym_2>\S+)$'
regex_new = r'(?P<sym_1>^\S+)\s+(?P<len_1>\S+)\s+(?P<off_1>\S+)\s+\|\s+(?P<state>\S+)\s+\((?P<weight>\S+)\)'


class Radiff2(Module):
    cmd = 'radiff'
    description = 'Diffing samples with radiff2'
    authors = ['TcM1911']

    def __init__(self):
        super(Radiff2, self).__init__()
        self.parser.add_argument('-v', '--verbose', action='store_true', help="Prints verbose logging")
        self.parser.add_argument('-n', '--nomatch', action='store_true', help='Include non matched functions')
        self.parser.add_argument('-s', '--samples', help="Samples to diff against")
        self.parser.add_argument('-a', '--all', action='store_true', help='Diff against all samples')
        self.parser.add_argument('-t', '--table', action='store_true', help='Create a "cluster" table')
        self.parser.add_argument('-e', '--export', help='In addition to print the table export it to a CSV file')

    def parse_line(self, line, parse_new):
        li = line.strip()
        m = re.search(regex_match, li)
        if m is None and parse_new:
            m = re.search(regex_new, li)
        return m

    def diff_files(self, file_a, file_b):
        cmd = ['radiff2', '-AA', '-C', '-q']
        cmd.append(file_a)
        cmd.append(file_b)
        out, err = Popen(cmd, stdout=PIPE, stderr=PIPE).communicate()
        return out.decode('utf-8').split('\n')

    def process_output(self, out, process_new):
        # The output from radiff2 includes an extra line at the end
        # so number of functions is one less.
        stats = {'total': len(out) - 1, 'match_count': float(0), 'partial_count': float(0)}
        matches = []
        partial = []
        new_sym = []
        for line in out:
            m = self.parse_line(line, process_new)
            if m is not None:
                state = m['state']
                if state == 'MATCH':
                    matches.append(m)
                    stats['match_count'] += float(m['weight'])
                elif state == 'UNMATCH':
                    partial.append(m)
                    stats['partial_count'] += float(m['weight'])
                elif state == 'NEW':
                    new_sym.append(m)
        stats['matches'] = len(matches)
        stats['partial'] = len(partial)
        if len(new_sym) == 0:
            # We have to calculate this because it wasn't extracted
            stats['no_match'] = stats['total'] - (stats['matches'] + stats['partial'])
        else:
            stats['no_match'] = len(new_sym)
        return (matches, partial, new_sym, stats)

    def print_stat(self, stats, sess_file, diff):
        a = stats['match_count'] + stats['partial_count']
        percent = 0
        if stats['total'] != 0:
            percent = round((a / float(stats['total'])) * 100, 2)
        out = 'Of {} functions in {}, {} match(es) and {} partially match(es) functions in {}'.format(
            stats['total'], diff, stats['matches'], stats['partial'], sess_file)
        self.log('success', out)
        frac = 'Code overlap is about {}%.'.format(percent)
        self.log('success', frac)

    def print_result(self, matches, parial, new_sym, sess_file, diff):
        header = ['fraction', sess_file + ' func', 'lenght', 'offset',
                  'offset', 'length', diff + ' func']
        if len(matches) > 0:
            self.log('success', 'Match')
            match_array = []
            for m in matches:
                match_array.append([m['weight'], m['sym_1'], m['len_1'], m['off_1'],
                                    m['off_2'], m['len_2'], m['sym_2']])
            self.log('table', dict(header=header, rows=match_array))
        if len(parial) > 0:
            self.log('success', 'Partial')
            partial_array = []
            for m in parial:
                partial_array.append([m['weight'], m['sym_1'], m['len_1'], m['off_1'],
                                      m['off_2'], m['len_2'], m['sym_2']])
            self.log('table', dict(header=header, rows=partial_array))
        if len(new_sym) > 0:
            self.log('success', 'No match')
            nomatch_array = []
            for m in new_sym:
                nomatch_array.append([m['sym_1'], m['len_1'], m['off_1']])
            nomatch_header = ['function', 'length', 'offset']
            self.log('table', dict(header=nomatch_header, rows=nomatch_array))

    def run(self):
        super(Radiff2, self).run()
        if self.args is None:
            return

        if not __sessions__.is_set() and not self.args.table:
            self.log('error', "No open session. This command expects a file to be open.")
            return

        db = Database()
        samples = None
        if self.args.samples:
            samples = db.find(key='any', value=self.args.samples)
        elif self.args.all:
            samples = db.find(key='all')
        else:
            samples = __sessions__.find

        if samples is None:
            self.log('error', "No samples found")
            return

        if self.args.table:
            table = []
            h = ['entry']
            sample_size = len(samples)
            self.log('info', 'Generating table, this might take a while...')
            for i in range(0, sample_size):
                h.append('(' + str(i+1) + ') ' + samples[i].name)
                mi = st.get_sample_path(samples[i].sha256)
                self.log('success', 'Processing sample: '+str(i+1) + ' of ' + str(sample_size))
                row = [i+1]
                for j in range(0, sample_size):
                    if i == j:
                        row.append(100)
                    else:
                        if self.args.verbose:
                            self.log('success', 'Comparing: ' + samples[i].name + ' to ' + samples[j].name)
                        sample = st.get_sample_path(samples[j].sha256)
                        out = self.diff_files(mi, sample)
                        match, part, no_match, stats = self.process_output(out, False)
                        a = stats['match_count'] + stats['partial_count']
                        percent = 0
                        if stats['total'] != 0:
                            percent = round((a / float(stats['total'])) * 100, 2)
                        row.append(percent)
                table.append(row)
            self.log('table', dict(rows=table, header=h))
            if self.args.export:
                file_path = os.path.abspath(os.path.expanduser(self.args.export))
                with open(file_path, 'w') as csvfile:
                    csvwriter = csv.writer(csvfile, delimiter=',')
                    csvwriter.writerow(h)
                    for row in table:
                        csvwriter.writerow(row)
            return

        session_file = __sessions__.current.file.name
        for malware in samples:
            if malware.sha256 == __sessions__.current.file.sha256:
                continue
            sample = st.get_sample_path(malware.sha256)
            out = self.diff_files(__sessions__.current.file.path, sample)
            match, part, no_match, stat = self.process_output(out, self.args.nomatch)
            if self.args.verbose:
                self.print_result(match, part, no_match, session_file, malware.name)
            self.print_stat(stat, session_file, malware.name)
