# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import math
from io import BytesIO, open

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    from elftools.elf.descriptions import describe_sh_flags
    from elftools.elf.descriptions import describe_p_flags
    from elftools.elf.descriptions import describe_symbol_type
    from elftools.elf.dynamic import DynamicSection
    HAVE_ELFTOOLS = True
except ImportError:
    HAVE_ELFTOOLS = False

from viper.common.out import bold
from viper.common.abstracts import Module
from viper.core.session import __sessions__
from viper.core.database import Database
from viper.core.storage import get_sample_path


# Have a look at scripts/readelf.py - pyelftools
class ELF(Module):
    cmd = 'elf'
    description = 'Extract information from ELF headers'
    authors = ['emdel']

    def __init__(self):
        super(ELF, self).__init__()
        subparsers = self.parser.add_subparsers(dest='subname')

        subparsers.add_parser('sections', help='List ELF sections')
        subparsers.add_parser('segments', help='List ELF segments')
        subparsers.add_parser('symbols', help='List ELF symbols')
        subparsers.add_parser('interpreter', help='Get the program interpreter')
        subparsers.add_parser('dynamic', help='Show the dynamic section')

        parser_ep = subparsers.add_parser('entrypoint', help='Show the ELF entry point')
        parser_ep.add_argument('-a', '--all', action='store_true', help='Print the entry point of all files in the project')
        parser_ep.add_argument('-c', '--cluster', action='store_true', help='Cluster all files in the project')
        parser_ep.add_argument('-s', '--scan', action='store_true', help='Scan repository for matching samples')

        parser_machine = subparsers.add_parser('machine', help='Show the ELF machine')
        parser_machine.add_argument('-a', '--all', action='store_true', help='Print the machine for all files in the project')
        parser_machine.add_argument('-c', '--cluster', action='store_true', help='Cluster all files in the project')
        parser_machine.add_argument('-s', '--scan', action='store_true', help='Scan repository for matching samples')

        parser_type = subparsers.add_parser('type', help='Show the ELF type')
        parser_type.add_argument('-a', '--all', action='store_true', help='Print the type of all files in the project')
        parser_type.add_argument('-c', '--cluster', action='store_true', help='Cluster all files in the project')
        parser_type.add_argument('-s', '--scan', action='store_true', help='Scan repository for matching samples')

        parser_ent = subparsers.add_parser('entropy', help='Show the ELF entropy')
        parser_ent.add_argument('-a', '--all', action='store_true', help='Print the entropy of all files in the project')
        parser_ent.add_argument('-c', '--cluster', action='store_true', help='Calculate and cluster all files in the project')
        parser_ent.add_argument('-s', '--scan', action='store_true', help='Scan repository for matching samples')

        self.elf = None

    def __check_session(self):
        if not __sessions__.is_set():
            self.log('error', "No open session")
            return False

        if not self.elf:
            try:
                self.elf = ELFFile(BytesIO(__sessions__.current.file.data))
            except Exception as e:
                self.log('error', "Unable to parse ELF file: {0}".format(e))
                return False

        return True

    def segments(self):
        if not self.__check_session():
            return

        rows = []
        for segment in self.elf.iter_segments():
            rows.append([
                segment['p_type'],
                segment['p_vaddr'],
                hex(segment['p_filesz']),
                hex(segment['p_memsz']),
                describe_p_flags(segment['p_flags']),
                self.get_entropy(segment.data())
            ])
        self.log('info', "ELF Segments:")
        self.log('table', dict(header=['Type', 'VirtAddr', 'FileSize', 'MemSize', 'Flags', 'Entropy'], rows=rows))

    def sections(self):
        if not self.__check_session():
            return

        rows = []
        # TODO: Add get_entropy in pyelftools sections
        for section in self.elf.iter_sections():
            rows.append([
                section.name,
                hex(section['sh_addr']),
                hex(section['sh_size']),
                section['sh_type'],
                describe_sh_flags(section['sh_flags']),
                self.get_entropy(section.data())
            ])

        self.log('info', "ELF Sections:")
        self.log('table', dict(header=['Name', 'Addr', 'Size', 'Type', 'Flags', 'Entropy'], rows=rows))

    def symbols(self):
        if not self.__check_session():
            return

        rows = []
        for section in self.elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue

            for cnt, symbol in enumerate(section.iter_symbols()):
                rows.append([
                    cnt,
                    hex(symbol['st_value']),
                    hex(symbol['st_size']),
                    describe_symbol_type(symbol['st_info']['type']),
                    symbol.name
                ])

        self.log('info', "ELF Symbols:")
        self.log('table', dict(header=['Num', 'Value', 'Size', 'Type', 'Name'], rows=rows))

    def interpreter(self):
        if not self.__check_session():
            return

        interp = None
        for segment in self.elf.iter_segments():
            if segment['p_type'] == 'PT_INTERP':
                interp = segment
                break
        if interp:
            self.log('', "Program interpreter: {0}".format(interp.get_interp_name()))
        else:
            self.log('error', "No PT_INTERP entry found")

    def dynamic(self):
        if not self.__check_session():
            return

        for section in self.elf.iter_sections():
            if not isinstance(section, DynamicSection):
                continue
            for tag in section.iter_tags():
                if tag.entry.d_tag != "DT_NEEDED":
                    continue
                self.log('info', tag.needed)

    def entrypoint(self):
        if not self.__check_session():
            return

        ep = self.elf.header.e_entry
        self.log('info', "Entry point: {0:#x}".format(ep))

        if self.args.scan and self.args.cluster:
            self.log('error', "You selected two exclusive options, pick one")
            return

        if self.args.all:
            db = Database()
            samples = db.find(key='all')

            rows = []
            for sample in samples:
                sample_path = get_sample_path(sample.sha256)
                if not os.path.exists(sample_path):
                    continue

                try:
                    with open(sample_path, 'rb') as fd:
                        elfo = ELFFile(fd)
                    cur_ep = elfo.header.e_entry
                except Exception:
                    continue

                rows.append([sample.md5, sample.name, hex(cur_ep)])

            self.log('table', dict(header=['MD5', 'Name', 'Entry point'], rows=rows))

            return

        if self.args.cluster:
            db = Database()
            samples = db.find(key='all')

            cluster = {}
            for sample in samples:
                sample_path = get_sample_path(sample.sha256)
                if not os.path.exists(sample_path):
                    continue

                try:
                    with open(sample_path, 'rb') as fd:
                        elfo = ELFFile(fd)
                    cur_ep = hex(elfo.header.e_entry)
                except Exception as e:
                    self.log('error', "Error {0} for sample {1}".format(e, sample.sha256))
                    continue

                if cur_ep not in cluster:
                    cluster[cur_ep] = []

                cluster[cur_ep].append([sample.md5, sample.name])

            for cluster_name, cluster_members in cluster.items():
                # Skipping clusters with only one entry.
                if len(cluster_members) == 1:
                    continue

                self.log('info', "ELF entry point cluster {0} with {1} elements".format(bold(cluster_name), len(cluster_members)))

                self.log('table', dict(header=['MD5', 'Name'], rows=cluster_members))

        if self.args.scan:
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
                    with open(sample_path, 'rb') as fd:
                        elfo = ELFFile(fd)
                    cur_ep = elfo.header.e_entry
                except Exception:
                    continue

                if ep == cur_ep:
                    rows.append([sample.md5, sample.name])

            if len(rows) > 0:
                self.log('info', "Following are samples with Entry point {0}".format(bold(ep)))
                self.log('table', dict(header=['MD5', 'Name'], rows=rows))

    def machine(self):
        if not self.__check_session():
            return

        machine = self.elf.header.e_machine
        self.log('info', "Machine: {0:s}".format(machine))

        if self.args.scan and self.args.cluster:
            self.log('error', "You selected two exclusive options, pick one")
            return

        if self.args.all:
            db = Database()
            samples = db.find(key='all')

            rows = []
            for sample in samples:
                sample_path = get_sample_path(sample.sha256)
                if not os.path.exists(sample_path):
                    continue

                try:
                    with open(sample_path, 'rb') as fd:
                        elfo = ELFFile(fd)
                    cur_machine = elfo.header.e_machine
                except Exception:
                    continue

                rows.append([sample.md5, sample.name, cur_machine])

            self.log('table', dict(header=['MD5', 'Name', 'e_machine'], rows=rows))

            return

        if self.args.cluster:
            db = Database()
            samples = db.find(key='all')

            cluster = {}
            for sample in samples:
                sample_path = get_sample_path(sample.sha256)
                if not os.path.exists(sample_path):
                    continue

                try:
                    with open(sample_path, 'rb') as fd:
                        elfo = ELFFile(fd)
                    cur_machine = elfo.header.e_machine
                except Exception as e:
                    self.log('error', "Error {0} for sample {1}".format(e, sample.sha256))
                    continue

                if cur_machine not in cluster:
                    cluster[cur_machine] = []

                cluster[cur_machine].append([sample.md5, sample.name])

            for cluster_name, cluster_members in cluster.items():
                # Skipping clusters with only one entry.
                if len(cluster_members) == 1:
                    continue

                self.log('info', "ELF e_machine cluster {0} with {1} elements".format(bold(cluster_name), len(cluster_members)))

                self.log('table', dict(header=['MD5', 'Name'], rows=cluster_members))

        if self.args.scan:
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
                    with open(sample_path, 'rb') as fd:
                        elfo = ELFFile(fd)
                    cur_machine = elfo.header.e_machine
                except Exception:
                    continue

                if machine == cur_machine:
                    rows.append([sample.md5, sample.name])

            if len(rows) > 0:
                self.log('info', "Following are samples with e_machine {0}".format(bold(machine)))
                self.log('table', dict(header=['MD5', 'Name'], rows=rows))

    def elftype(self):
        if not self.__check_session():
            return

        e_type = self.elf.header.e_type
        self.log('info', "ELF type: {0:s}".format(e_type))

        if self.args.scan and self.args.cluster:
            self.log('error', "You selected two exclusive options, pick one")
            return

        if self.args.all:
            db = Database()
            samples = db.find(key='all')

            rows = []
            for sample in samples:
                sample_path = get_sample_path(sample.sha256)
                if not os.path.exists(sample_path):
                    continue

                try:
                    with open(sample_path, 'rb') as fd:
                        elfo = ELFFile(fd)
                    cur_e_type = elfo.header.e_type
                except Exception:
                    continue

                rows.append([sample.md5, sample.name, cur_e_type])

            self.log('table', dict(header=['MD5', 'Name', 'e_type'], rows=rows))

            return

        if self.args.cluster:
            db = Database()
            samples = db.find(key='all')

            cluster = {}
            for sample in samples:
                sample_path = get_sample_path(sample.sha256)
                if not os.path.exists(sample_path):
                    continue

                try:
                    with open(sample_path, 'rb') as fd:
                        elfo = ELFFile(fd)
                    cur_e_type = elfo.header.e_type
                except Exception as e:
                    self.log('error', "Error {0} for sample {1}".format(e, sample.sha256))
                    continue

                if cur_e_type not in cluster:
                    cluster[cur_e_type] = []

                cluster[cur_e_type].append([sample.md5, sample.name])

            for cluster_name, cluster_members in cluster.items():
                # Skipping clusters with only one entry.
                if len(cluster_members) == 1:
                    continue

                self.log('info', "ELF e_type cluster {0} with {1} elements".format(bold(cluster_name), len(cluster_members)))

                self.log('table', dict(header=['MD5', 'Name'], rows=cluster_members))

        if self.args.scan:
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
                    with open(sample_path, 'rb') as fd:
                        elfo = ELFFile(fd)
                    cur_e_type = elfo.header.e_machine
                except Exception:
                    continue
                if e_type == cur_e_type:
                    rows.append([sample.md5, sample.name])

            if len(rows) > 0:
                self.log('info', "Following are samples with ELF type {0}".format(bold(e_type)))
                self.log('table', dict(header=['MD5', 'Name'], rows=rows))

    def elfentropy(self):
        if not self.__check_session():
            return

        ent = self.get_entropy(__sessions__.current.file.data)
        self.log('info', "Entropy {0}".format(ent))
        if ent > 7:
            self.log('warning', "Probably packed. High entropy.")

        if self.args.scan and self.args.cluster:
            self.log('error', "You selected two exclusive options, pick one")
            return

        if self.args.all:
            db = Database()
            samples = db.find(key='all')

            rows = []
            for sample in samples:
                sample_path = get_sample_path(sample.sha256)
                if not os.path.exists(sample_path):
                    continue

                try:
                    with open(sample_path, 'rb') as fd:
                        cur_ent = self.get_entropy(fd.read())
                except Exception as e:
                    self.log('error', "Error {0} for sample {1}".format(e, sample.sha256))
                    continue

                rows.append([sample.md5, sample.name, cur_ent])

            self.log('table', dict(header=['MD5', 'Name', 'Entropy'], rows=rows))

            return

        if self.args.cluster:
            db = Database()
            samples = db.find(key='all')

            cluster = {}
            for sample in samples:
                sample_path = get_sample_path(sample.sha256)
                if not os.path.exists(sample_path):
                    continue

                try:
                    with open(sample_path, 'rb') as fd:
                        cur_ent = self.get_entropy(fd.read())
                except Exception as e:
                    self.log('error', "Error {0} for sample {1}".format(e, sample.sha256))
                    continue

                if cur_ent not in cluster:
                    cluster[cur_ent] = []

                cluster[cur_ent].append([sample.md5, sample.name])

            for cluster_name, cluster_members in cluster.items():
                # Skipping clusters with only one entry.
                if len(cluster_members) == 1:
                    continue

                self.log('info', "ELF entropy cluster {0} with {1} elements".format(bold(cluster_name), len(cluster_members)))

                self.log('table', dict(header=['MD5', 'Name'], rows=cluster_members))

        if self.args.scan:
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
                    with open(sample_path, 'rb') as fd:
                        cur_ent = self.get_entropy(fd.read())
                except Exception:
                    continue

                if ent == cur_ent:
                    rows.append([sample.md5, sample.name])

            if len(rows) > 0:
                self.log('info', "Following are samples with entropy {0}".format(bold(ent)))
                self.log('table', dict(header=['MD5', 'Name'], rows=rows))

    def get_entropy(self, data):
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(bytes(x))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        ent = "%.4f" % entropy
        return float(ent)

    def run(self):
        super(ELF, self).run()
        if self.args is None:
            return

        if not HAVE_ELFTOOLS:
            self.log('error', "Missing dependency, install pyelftools (`pip install pyelftools`)")
            return

        if self.args.subname == "sections":
            self.sections()
        elif self.args.subname == "segments":
            self.segments()
        elif self.args.subname == "symbols":
            self.symbols()
        elif self.args.subname == "interpreter":
            self.interpreter()
        elif self.args.subname == "dynamic":
            self.dynamic()
        elif self.args.subname == "entrypoint":
            self.entrypoint()
        elif self.args.subname == "machine":
            self.machine()
        elif self.args.subname == "type":
            self.elftype()
        elif self.args.subname == "entropy":
            self.elfentropy()
        else:
            self.log('error', 'At least one of the parameters is required')
            self.usage()
