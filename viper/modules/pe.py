# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import os
import re
import datetime
import tempfile
import time
from io import BytesIO, open

from viper.common.constants import VIPER_ROOT

try:
    import pefile
    import peutils
    HAVE_PEFILE = True
except ImportError:
    HAVE_PEFILE = False

try:
    from .pehash.pehasher import calculate_pehash
    HAVE_PEHASH = True
except ImportError:
    HAVE_PEHASH = False

try:
    from .sigs_helper.sigs_helper import get_auth_data
    from .verifysigs.asn1utils import dn
    HAVE_VERIFYSIGS = True
except ImportError:
    HAVE_VERIFYSIGS = False

from viper.common.out import bold
from viper.common.abstracts import Module
from viper.common.utils import get_type, get_md5
from viper.core.database import Database
from viper.core.storage import get_sample_path
from viper.core.session import __sessions__


class PE(Module):
    cmd = 'pe'
    description = 'Extract information from PE32 headers'
    authors = ['nex', 'Statixs']

    def __init__(self):
        super(PE, self).__init__()
        subparsers = self.parser.add_subparsers(dest='subname')
        subparsers.add_parser('imports', help='List PE imports')
        subparsers.add_parser('exports', help='List PE exports')

        parser_ep = subparsers.add_parser('entrypoint', help='Show and scan for AddressOfEntryPoint')
        parser_ep.add_argument('-a', '--all', action='store_true', help='Prints the AddressOfEntryPoint of all files in the project')
        parser_ep.add_argument('-c', '--cluster', action='store_true', help='Cluster all files in the project')
        parser_ep.add_argument('-s', '--scan', action='store_true', help='Scan repository for matching samples')

        parser_res = subparsers.add_parser('resources', help='List PE resources')
        parser_res.add_argument('-d', '--dump', metavar='folder', help='Destination directory to store resource files in')
        parser_res.add_argument('-o', '--open', metavar='resource number', type=int, help='Open a session on the specified resource')
        parser_res.add_argument('-s', '--scan', action='store_true', help='Scan the repository for common resources')

        parser_imp = subparsers.add_parser('imphash', help='Get and scan for imphash')
        parser_imp.add_argument('-s', '--scan', action='store_true', help='Scan for all samples with same imphash')
        parser_imp.add_argument('-c', '--cluster', action='store_true', help='Cluster repository by imphash (careful, could be massive)')

        parser_comp = subparsers.add_parser('compiletime', help='Show the compiletime')
        parser_comp.add_argument('-a', '--all', action='store_true', help='Retrieve compile time for all stored samples')
        parser_comp.add_argument('-s', '--scan', action='store_true', help='Scan the repository for common compile time')
        parser_comp.add_argument('-w', '--window', type=int, help='Specify an optional time window in minutes')

        parser_peid = subparsers.add_parser('peid', help='Show the PEiD signatures')
        parser_peid.add_argument('-s', '--scan', action='store_true', help='Scan the repository for PEiD signatures')

        parser_sec = subparsers.add_parser('security', help='Show digital signature')
        parser_sec.add_argument('-d', '--dump', metavar='folder', help='Destination directory to store digital signature in')
        parser_sec.add_argument('-a', '--all', action='store_true', help='Find all samples with a digital signature')
        parser_sec.add_argument('-s', '--scan', action='store_true', help='Scan the repository for common certificates')
        parser_sec.add_argument('-c', '--check', action='store_true', help='Check authenticode information')

        parser_lang = subparsers.add_parser('language', help='Guess PE language')
        parser_lang.add_argument('-s', '--scan', action='store_true', help='Scan the repository')

        parser_sect = subparsers.add_parser('sections', help='List PE Sections')
        parser_sect.add_argument('-d', '--dump', metavar='folder', help='Destionation directory to dump all sections in')

        parser_peh = subparsers.add_parser('pehash', help='Calculate the PEhash and compare them')
        parser_peh.add_argument('-a', '--all', action='store_true', help='Prints the PEhash of all files in the project')
        parser_peh.add_argument('-c', '--cluster', action='store_true', help='Calculate and cluster all files in the project')
        parser_peh.add_argument('-s', '--scan', action='store_true', help='Scan repository for matching samples')

        self.pe = None

        self.result_compile_time = None
        self.result_sections = None

    def __check_session(self):
        if not __sessions__.is_set():
            self.log('error', "No open session")
            return False

        if not self.pe:
            try:
                self.pe = pefile.PE(data=__sessions__.current.file.data)
            except pefile.PEFormatError as e:
                self.log('error', "Unable to parse PE file: {0}".format(e))
                return False

        return True

    def imports(self):
        if not self.__check_session():
            return

        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                try:
                    if isinstance(entry.dll, bytes):
                        dll = entry.dll.decode()
                    else:
                        dll = entry.dll
                    self.log('info', "DLL: {0}".format(dll))
                    for symbol in entry.imports:
                        if isinstance(symbol.name, bytes):
                            name = symbol.name.decode()
                        else:
                            name = symbol.name
                        self.log('item', "{0}: {1}".format(hex(symbol.address), name))
                except:
                    continue

    def exports(self):
        if not self.__check_session():
            return

        self.log('info', "Exports:")
        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            for symbol in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                self.log('item', "{0}: {1} ({2})".format(hex(self.pe.OPTIONAL_HEADER.ImageBase + symbol.address), symbol.name, symbol.ordinal))

    def entrypoint(self):
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
                    cur_ep = pefile.PE(sample_path).OPTIONAL_HEADER.AddressOfEntryPoint
                except:
                    continue

                rows.append([sample.md5, sample.name, cur_ep])

            self.log('table', dict(header=['MD5', 'Name', 'AddressOfEntryPoint'], rows=rows))

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
                    cur_ep = pefile.PE(sample_path).OPTIONAL_HEADER.AddressOfEntryPoint
                except:
                    continue

                if cur_ep not in cluster:
                    cluster[cur_ep] = []

                cluster[cur_ep].append([sample.md5, sample.name])

            for cluster_name, cluster_members in cluster.items():
                # Skipping clusters with only one entry.
                if len(cluster_members) == 1:
                    continue

                self.log('info', "AddressOfEntryPoint cluster {0}".format(bold(cluster_name)))

                self.log('table', dict(header=['MD5', 'Name'], rows=cluster_members))

            return

        if not self.__check_session():
            return

        ep = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint

        self.log('info', "AddressOfEntryPoint: {0}".format(ep))

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
                    cur_ep = pefile.PE(sample_path).OPTIONAL_HEADER.AddressOfEntryPoint
                except:
                    continue

                if ep == cur_ep:
                    rows.append([sample.md5, sample.name])

            self.log('info', "Following are samples with AddressOfEntryPoint {0}".format(bold(ep)))

            self.log('table', dict(header=['MD5', 'Name'], rows=rows))

    def compiletime(self):

        def get_compiletime(pe):
            return "{0} ({1})".format(pe.FILE_HEADER.TimeDateStamp, datetime.datetime.utcfromtimestamp(pe.FILE_HEADER.TimeDateStamp))

        if self.args.all:
            self.log('info', "Retrieving compile time for all stored samples...")

            db = Database()
            samples = db.find(key='all')

            results = []
            for sample in samples:
                sample_path = get_sample_path(sample.sha256)

                try:
                    cur_pe = pefile.PE(sample_path)
                    cur_compile_time = get_compiletime(cur_pe)
                except:
                    continue

                results.append([sample.name, sample.md5, cur_compile_time])

            if len(results) > 0:
                self.log('table', dict(header=['Name', 'MD5', 'Compile Time'], rows=results))

            return

        if not self.__check_session():
            return

        self.result_compile_time = get_compiletime(self.pe)
        compile_time = self.result_compile_time
        self.log('info', "Compile Time: {0}".format(bold(compile_time)))

        if self.args.scan:
            self.log('info', "Scanning the repository for matching samples...")

            db = Database()
            samples = db.find(key='all')

            matches = []
            for sample in samples:
                if sample.sha256 == __sessions__.current.file.sha256:
                    continue

                sample_path = get_sample_path(sample.sha256)
                if not os.path.exists(sample_path):
                    continue

                try:
                    cur_pe = pefile.PE(sample_path)
                    cur_compile_time = get_compiletime(cur_pe)
                except:
                    continue

                if compile_time == cur_compile_time:
                    matches.append([sample.name, sample.md5, cur_compile_time])
                else:
                    if self.args.window:
                        if cur_compile_time > compile_time:
                            delta = (cur_compile_time - compile_time)
                        elif cur_compile_time < compile_time:
                            delta = (compile_time - cur_compile_time)

                        delta_minutes = int(delta.total_seconds()) / 60
                        if delta_minutes <= self.args.window:
                            matches.append([sample.name, sample.md5, cur_compile_time])

            self.log('info', "{0} relevant matches found".format(bold(len(matches))))

            if len(matches) > 0:
                self.log('table', dict(header=['Name', 'MD5', 'Compile Time'], rows=matches))

    def peid(self):

        def get_signatures():
            userdb_path = None
            for path_attempt in ['/usr/share/viper/peid/UserDB.TXT', os.path.join(VIPER_ROOT, 'data/peid/UserDB.TXT')]:
                if os.path.exists(path_attempt):
                    userdb_path = path_attempt
                    break

            if not userdb_path:
                return

            with open(userdb_path, 'rb') as f:
                sig_data = f.read()

            signatures = peutils.SignatureDatabase(data=sig_data)

            return signatures

        def get_matches(pe, signatures):
            matches = signatures.match_all(pe, ep_only=True)
            return matches

        if not self.__check_session():
            return

        signatures = get_signatures()
        peid_matches = get_matches(self.pe, signatures)

        if peid_matches:
            self.log('info', "PEiD Signatures:")
            for sig in peid_matches:
                if type(sig) is list:
                    self.log('item', sig[0])
                else:
                    self.log('item', sig)
        else:
            self.log('info', "No PEiD signatures matched.")

        if self.args.scan and peid_matches:
            self.log('info', "Scanning the repository for matching samples...")

            db = Database()
            samples = db.find(key='all')

            matches = []
            for sample in samples:
                if sample.sha256 == __sessions__.current.file.sha256:
                    continue

                sample_path = get_sample_path(sample.sha256)
                if not os.path.exists(sample_path):
                    continue

                try:
                    cur_pe = pefile.PE(sample_path)
                    cur_peid_matches = get_matches(cur_pe, signatures)
                except:
                    continue

                if peid_matches == cur_peid_matches:
                    matches.append([sample.name, sample.sha256])

            self.log('info', "{0} relevant matches found".format(bold(len(matches))))

            if len(matches) > 0:
                self.log('table', dict(header=['Name', 'SHA256'], rows=matches))

    def resources(self):

        # Use this function to retrieve resources for the given PE instance.
        # Returns all the identified resources with indicators and attributes.
        def get_resources(pe):
            resources = []
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                count = 1
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    try:
                        resource = {}

                        if resource_type.name is not None:
                            name = str(resource_type.name)
                        else:
                            name = str(pefile.RESOURCE_TYPE.get(resource_type.struct.Id))

                        if name is None:
                            name = str(resource_type.struct.Id)

                        if hasattr(resource_type, 'directory'):
                            for resource_id in resource_type.directory.entries:
                                if hasattr(resource_id, 'directory'):
                                    for resource_lang in resource_id.directory.entries:
                                        data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                        filetype = get_type(data)
                                        md5 = get_md5(data)
                                        language = pefile.LANG.get(resource_lang.data.lang, None)
                                        sublanguage = pefile.get_sublang_name_for_lang(resource_lang.data.lang, resource_lang.data.sublang)
                                        offset = ('%-8s' % hex(resource_lang.data.struct.OffsetToData)).strip()
                                        size = ('%-8s' % hex(resource_lang.data.struct.Size)).strip()

                                        resource = [count, name, offset, md5, size, filetype, language, sublanguage]

                                        # Dump resources if requested to and if the file currently being
                                        # processed is the opened session file.
                                        # This is to avoid that during a --scan all the resources being
                                        # scanned are dumped as well.
                                        if (self.args.open or self.args.dump) and pe == self.pe:
                                            if self.args.dump:
                                                folder = self.args.dump
                                            else:
                                                folder = tempfile.mkdtemp()

                                            resource_path = os.path.join(folder, '{0}_{1}_{2}'.format(__sessions__.current.file.md5, offset, name))
                                            resource.append(resource_path)

                                            with open(resource_path, 'wb') as resource_handle:
                                                resource_handle.write(data)

                                        resources.append(resource)

                                        count += 1
                    except Exception as e:
                        self.log('error', e)
                        continue

            return resources

        if not self.__check_session():
            return

        # Obtain resources for the currently opened file.
        resources = get_resources(self.pe)

        if not resources:
            self.log('warning', "No resources found")
            return

        headers = ['#', 'Name', 'Offset', 'MD5', 'Size', 'File Type', 'Language', 'Sublanguage']
        if self.args.dump or self.args.open:
            headers.append('Dumped To')

        self.log('table', dict(header=headers, rows=resources))

        # If instructed, open a session on the given resource.
        if self.args.open:
            for resource in resources:
                if resource[0] == self.args.open:
                    __sessions__.new(resource[8])
                    return
        # If instructed to perform a scan across the repository, start looping
        # through all available files.
        elif self.args.scan:
            self.log('info', "Scanning the repository for matching samples...")

            # Retrieve list of samples stored locally and available in the
            # database.
            db = Database()
            samples = db.find(key='all')

            matches = []
            for sample in samples:
                # Skip if it's the same file.
                if sample.sha256 == __sessions__.current.file.sha256:
                    continue

                # Obtain path to the binary.
                sample_path = get_sample_path(sample.sha256)
                if not os.path.exists(sample_path):
                    continue

                # Open PE instance.
                try:
                    cur_pe = pefile.PE(sample_path)
                except:
                    continue

                # Obtain the list of resources for the current iteration.
                cur_resources = get_resources(cur_pe)
                matched_resources = []
                # Loop through entry's resources.
                for cur_resource in cur_resources:
                    # Loop through opened file's resources.
                    for resource in resources:
                        # If there is a common resource, add it to the list.
                        if cur_resource[3] == resource[3]:
                            matched_resources.append(resource[3])

                # If there are any common resources, add the entry to the list
                # of matched samples.
                if len(matched_resources) > 0:
                    matches.append([sample.name, sample.md5, '\n'.join(r for r in matched_resources)])

            self.log('info', "{0} relevant matches found".format(bold(len(matches))))

            if len(matches) > 0:
                self.log('table', dict(header=['Name', 'MD5', 'Resource MD5'], rows=matches))

    def imphash(self):
        if self.args.scan and self.args.cluster:
            self.log('error', "You selected two exclusive options, pick one")
            return

        if self.args.cluster:
            self.log('info', "Clustering all samples by imphash...")

            db = Database()
            samples = db.find(key='all')

            cluster = {}
            for sample in samples:
                sample_path = get_sample_path(sample.sha256)
                if not os.path.exists(sample_path):
                    continue

                try:
                    cur_imphash = pefile.PE(sample_path).get_imphash()
                except:
                    continue

                if cur_imphash not in cluster:
                    cluster[cur_imphash] = []

                cluster[cur_imphash].append([sample.md5, sample.name])

            for cluster_name, cluster_members in cluster.items():
                # Skipping clusters with only one entry.
                if len(cluster_members) == 1:
                    continue

                self.log('info', "Imphash cluster {0}".format(bold(cluster_name)))

                self.log('table', dict(header=['MD5', 'Name'], rows=cluster_members))

            return

        if self.__check_session():
            try:
                imphash = self.pe.get_imphash()
            except AttributeError:
                self.log('error', "No imphash support, upgrade pefile to a version >= 1.2.10-139 (`pip install --upgrade pefile`)")
                return

            self.log('info', "Imphash: {0}".format(bold(imphash)))

            if self.args.scan:
                self.log('info', "Scanning the repository for matching samples...")

                db = Database()
                samples = db.find(key='all')

                matches = []
                for sample in samples:
                    if sample.sha256 == __sessions__.current.file.sha256:
                        continue

                    sample_path = get_sample_path(sample.sha256)
                    if not os.path.exists(sample_path):
                        continue

                    try:
                        cur_imphash = pefile.PE(sample_path).get_imphash()
                    except:
                        continue

                    if imphash == cur_imphash:
                        matches.append([sample.name, sample.sha256])

                self.log('info', "{0} relevant matches found".format(bold(len(matches))))

                if len(matches) > 0:
                    self.log('table', dict(header=['Name', 'SHA256'], rows=matches))

    def security(self):

        def get_certificate(pe):
            # TODO: this only extract the raw list of certificate data.
            # I need to parse them, extract single certificates and perhaps return
            # the PEM data of the first certificate only.
            pe_security_dir = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
            address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pe_security_dir].VirtualAddress
            #  size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pe_security_dir].Size

            if address:
                return pe.write()[address + 8:]
            else:
                return None

        def get_signed_samples(current=None, cert_filter=None):
            db = Database()
            samples = db.find(key='all')

            results = []
            for sample in samples:
                # Skip if it's the same file.
                if current:
                    if sample.sha256 == current:
                        continue

                # Obtain path to the binary.
                sample_path = get_sample_path(sample.sha256)
                if not os.path.exists(sample_path):
                    continue

                # Open PE instance.
                try:
                    cur_pe = pefile.PE(sample_path)
                except:
                    continue

                cur_cert_data = get_certificate(cur_pe)

                if not cur_cert_data:
                    continue

                cur_cert_md5 = get_md5(cur_cert_data)

                if cert_filter:
                    if cur_cert_md5 == cert_filter:
                        results.append([sample.name, sample.md5])
                else:
                    results.append([sample.name, sample.md5, cur_cert_md5])

            return results

        if self.args.all:
            self.log('info', "Scanning the repository for all signed samples...")

            all_of_them = get_signed_samples()

            self.log('info', "{0} signed samples found".format(bold(len(all_of_them))))

            if len(all_of_them) > 0:
                self.log('table', dict(header=['Name', 'MD5', 'Cert MD5'], rows=all_of_them))

            return

        if not self.__check_session():
            return

        cert_data = get_certificate(self.pe)

        if not cert_data:
            self.log('warning', "No certificate found")
            return

        cert_md5 = get_md5(cert_data)

        self.log('info', "Found certificate with MD5 {0}".format(bold(cert_md5)))

        if self.args.dump:
            cert_path = os.path.join(self.args.dump, '{0}.crt'.format(__sessions__.current.file.sha256))
            with open(cert_path, 'wb+') as cert_handle:
                cert_handle.write(cert_data)

            self.log('info', "Dumped certificate to {0}".format(cert_path))
            self.log('info', "You can parse it using the following command:\n\t" +
                     bold("openssl pkcs7 -inform DER -print_certs -text -in {0}".format(cert_path)))

        # TODO: do scan for certificate's serial number.
        if self.args.scan:
            self.log('info', "Scanning the repository for matching signed samples...")

            matches = get_signed_samples(current=__sessions__.current.file.sha256, cert_filter=cert_md5)

            self.log('info', "{0} relevant matches found".format(bold(len(matches))))

            if len(matches) > 0:
                self.log('table', dict(header=['Name', 'SHA256'], rows=matches))

        # TODO: this function needs to be better integrated with the rest of the command.
        # TODO: need to add more error handling and figure out why so many samples are failing.
        if self.args.check:
            if not HAVE_VERIFYSIGS:
                self.log('error', "Dependencies missing for authenticode validation. Please install M2Crypto and pyasn1 (`pip install pyasn1 M2Crypto`)")
                return

            try:
                auth, computed_content_hash = get_auth_data(__sessions__.current.file.path)
            except Exception as e:
                self.log('error', "Unable to parse PE certificate: {0}".format(str(e)))
                return

            try:
                auth.ValidateAsn1()
                auth.ValidateHashes(computed_content_hash)
                auth.ValidateSignatures()
                auth.ValidateCertChains(time.gmtime())
            except Exception as e:
                self.log('error', "Unable to validate PE certificate: {0}".format(str(e)))
                return

            self.log('info', bold('Signature metadata:'))
            self.log('info', 'Program name: {0}'.format(auth.program_name))
            self.log('info', 'URL: {0}'.format(auth.program_url))

            if auth.has_countersignature:
                self.log('info', bold('Countersignature is present. Timestamp: {0} UTC'.format(
                         time.asctime(time.gmtime(auth.counter_timestamp)))))
            else:
                self.log('info', bold('Countersignature is not present.'))

            self.log('info', bold('Binary is signed with cert issued by:'))
            self.log('info', '{0}'.format(auth.signing_cert_id[0]))

            self.log('info', '{0}'.format(auth.cert_chain_head[2][0]))
            self.log('info', 'Chain not before: {0} UTC'.format(
                     time.asctime(time.gmtime(auth.cert_chain_head[0]))))
            self.log('info', 'Chain not after: {0} UTC'.format(
                     time.asctime(time.gmtime(auth.cert_chain_head[1]))))

            if auth.has_countersignature:
                self.log('info', bold('Countersig chain head issued by:'))
                self.log('info', '{0}'.format(auth.counter_chain_head[2]))
                self.log('info', 'Countersig not before: {0} UTC'.format(
                         time.asctime(time.gmtime(auth.counter_chain_head[0]))))
                self.log('info', 'Countersig not after: {0} UTC'.format(
                         time.asctime(time.gmtime(auth.counter_chain_head[1]))))

            self.log('info', bold('Certificates:'))
            for (issuer, serial), cert in auth.certificates.items():
                self.log('info', 'Issuer: {0}'.format(issuer))
                self.log('info', 'Serial: {0}'.format(serial))
                subject = cert[0][0]['subject']
                subject_dn = str(dn.DistinguishedName.TraverseRdn(subject[0]))
                self.log('info', 'Subject: {0}'.format(subject_dn))
                not_before = cert[0][0]['validity']['notBefore']
                not_after = cert[0][0]['validity']['notAfter']
                not_before_time = not_before.ToPythonEpochTime()
                not_after_time = not_after.ToPythonEpochTime()
                self.log('info', 'Not Before: {0} UTC ({1})'.format(
                         time.asctime(time.gmtime(not_before_time)), not_before[0]))
                self.log('info', 'Not After: {0} UTC ({1})'.format(
                         time.asctime(time.gmtime(not_after_time)), not_after[0]))

            if auth.trailing_data:
                self.log('info', 'Signature Blob had trailing (unvalidated) data ({0} bytes): {1}'.format(
                         len(auth.trailing_data), auth.trailing_data.encode('hex')))

    def language(self):

        def get_iat(pe):
            iat = []
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for peimport in pe.DIRECTORY_ENTRY_IMPORT:
                    iat.append(peimport.dll)

            return iat

        def check_module(iat, match):
            for imp in iat:
                if imp.find(match) != -1:
                    return True

            return False

        def is_cpp(data, cpp_count):
            for line in data:
                if b'type_info' in line or b'RTTI' in line:
                    cpp_count += 1
                    break

            if cpp_count == 2:
                return True

            return False

        def is_delphi(data):
            for line in data:
                if b'Borland' in line:
                    path = line.split(b'\\')
                    for p in path:
                        if b'Delphi' in p:
                            return True
            return False

        def is_vbdotnet(data):
            for line in data:
                if b'Compiler' in line:
                    stuff = line.split(b'.')
                    if b'VisualBasic' in stuff:
                        return True

            return False

        def is_autoit(data):
            for line in data:
                if b'AU3!' in line:
                    return True

            return False

        def is_packed(pe):
            for section in pe.sections:
                if section.get_entropy() > 7:
                    return True

            return False

        def get_strings(content):
            regexp = b'[\x30-\x39\x41-\x5f\x61-\x7a\-\.:]{4,}'
            return re.findall(regexp, content)

        def find_language(iat, sample, content):
            dotnet = False
            cpp_count = 0
            found = None

            # VB check
            if check_module(iat, 'VB'):
                self.log('info', "{0} - Possible language: Visual Basic".format(sample.name))
                return 'Visual Basic'

            # .NET check
            if check_module(iat, 'mscoree.dll') and not found:
                dotnet = True
                found = '.NET'

            # C DLL check
            if not found and (check_module(iat, 'msvcr') or check_module(iat, 'MSVCR') or check_module(iat, 'c++')):
                cpp_count += 1

            if not found:
                data = get_strings(content)

                if is_cpp(data, cpp_count) and not found:
                    found = 'CPP'
                if not found and cpp_count == 1:
                    found = 'C'
                if not dotnet and is_delphi(data) and not found:
                    found = 'Delphi'
                if dotnet and is_vbdotnet(data):
                    found = 'Visual Basic .NET'
                if is_autoit(data) and not found:
                    found = 'AutoIt'

            return found

        if not self.__check_session():
            return

        if is_packed(self.pe):
            self.log('warning', "Probably packed, the language guess might be unreliable")

        language = find_language(
            get_iat(self.pe),
            __sessions__.current.file,
            __sessions__.current.file.data
        )

        if language:
            self.log('info', "Probable language: {0}".format(bold(language)))
        else:
            self.log('error', "Programming language not identified")
            return

        if self.args.scan:
            self.log('info', "Scanning the repository for matching samples...")

            db = Database()
            samples = db.find(key='all')

            matches = []
            for sample in samples:
                if sample.sha256 == __sessions__.current.file.sha256:
                    continue

                sample_path = get_sample_path(sample.sha256)

                if not os.path.exists(sample_path):
                    continue

                try:
                    cur_pe = pefile.PE(sample_path)
                except pefile.PEFormatError:
                    continue

                cur_packed = ''
                if is_packed(cur_pe):
                    cur_packed = 'Yes'

                cur_language = find_language(
                    get_iat(cur_pe),
                    sample,
                    open(sample_path, 'rb').read()
                )

                if not cur_language:
                    continue

                if cur_language == language:
                    matches.append([sample.name, sample.md5, cur_packed])

            if matches:
                self.log('table', dict(header=['Name', 'MD5', 'Is Packed'], rows=matches))
            else:
                self.log('info', "No matches found")

    def sections(self):
        if not self.__check_session():
            return

        rows = []
        for section in self.pe.sections:
            if isinstance(section.Name, bytes):
                section_name = section.Name.decode()
            else:
                section_name = section.Name
            section_name = section_name.replace('\x00', '')
            if self.args.dump:
                file_handle = BytesIO(__sessions__.current.file.data)
                file_handle.seek(int(section.PointerToRawData))
                section_data = file_handle.read(int(section.SizeOfRawData))

                dump_path = os.path.join(self.args.dump, '{}_{}.bin'.format(
                    __sessions__.current.file.md5, section_name))

                with open(dump_path, 'wb') as dump_handle:
                    dump_handle.write(section_data)

                self.log('info', "Dumped section to {}".format(dump_path))
            rows.append([
                section_name,
                hex(section.VirtualAddress),
                hex(section.Misc_VirtualSize),
                section.PointerToRawData,
                section.SizeOfRawData,
                section.get_entropy()
            ])

        self.result_sections = rows
        self.log('info', "PE Sections:")
        self.log('table', dict(header=['Name', 'RVA', 'VirtualSize', 'PointerToRawData', 'RawDataSize', 'Entropy'], rows=rows))

    def pehash(self):
        if not HAVE_PEHASH:
            self.log('error', "PEhash is missing. Please copy PEhash to the modules directory of Viper")
            return

        current_pehash = None
        if __sessions__.is_set():
            current_pehash = calculate_pehash(data=__sessions__.current.file.data)
            self.log('info', "PEhash: {0}".format(bold(current_pehash)))

        if self.args.all or self.args.cluster or self.args.scan:
            db = Database()
            samples = db.find(key='all')

            rows = []
            for sample in samples:
                sample_path = get_sample_path(sample.sha256)
                pe_hash = calculate_pehash(sample_path)
                if pe_hash:
                    rows.append((sample.name, sample.md5, pe_hash))

        if self.args.all:
            self.log('info', "PEhash for all files:")
            header = ['Name', 'MD5', 'PEhash']
            self.log('table', dict(header=header, rows=rows))

        elif self.args.cluster:
            self.log('info', "Clustering files by PEhash...")

            cluster = {}
            for sample_name, sample_md5, pe_hash in rows:
                cluster.setdefault(pe_hash, []).append([sample_name, sample_md5])

            for item in cluster.items():
                if len(item[1]) > 1:
                    self.log('info', "PEhash cluster {0}:".format(bold(item[0])))
                    self.log('table', dict(header=['Name', 'MD5'], rows=item[1]))

        elif self.args.scan:
            if __sessions__.is_set() and current_pehash:
                self.log('info', "Finding matching samples...")

                matches = []
                for row in rows:
                    if row[1] == __sessions__.current.file.md5:
                        continue

                    if row[2] == current_pehash:
                        matches.append([row[0], row[1]])

                if matches:
                    self.log('table', dict(header=['Name', 'MD5'], rows=matches))
                else:
                    self.log('info', "No matches found")

    def run(self):
        super(PE, self).run()
        if self.args is None:
            return

        if not HAVE_PEFILE:
            self.log('error', "Missing dependency, install pefile (`pip install pefile`)")
            return

        if self.args.subname == 'imports':
            self.imports()
        elif self.args.subname == 'exports':
            self.exports()
        elif self.args.subname == 'resources':
            self.resources()
        elif self.args.subname == 'imphash':
            self.imphash()
        elif self.args.subname == 'compiletime':
            self.compiletime()
        elif self.args.subname == 'peid':
            self.peid()
        elif self.args.subname == 'security':
            self.security()
        elif self.args.subname == 'sections':
            self.sections()
        elif self.args.subname == 'language':
            self.language()
        elif self.args.subname == 'pehash':
            self.pehash()
        elif self.args.subname == 'entrypoint':
            self.entrypoint()
