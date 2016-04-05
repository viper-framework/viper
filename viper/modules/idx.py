# Originally written by Brian Baskin (@bbaskin):
# https://github.com/Rurik/Java_IDX_Parser
# See the file 'LICENSE' for copying permission.

import struct
import time
import zlib

from viper.common.abstracts import Module
from viper.core.session import __sessions__


class IDX(Module):
    cmd = 'idx'
    description = 'Parse Java IDX files'
    authors = ['Kevin Breen']

    def __init__(self):
        super(IDX, self).__init__()

    def run(self):

        def sec2_parse():
            """Parse Section Two from 6.03 and greater files.

            Section two contains all download history data
            """
            sec_two = []
            data.seek(128)
            len_URL = struct.unpack('>l', data.read(4))[0]
            data_URL = data.read(len_URL)
            len_IP = struct.unpack('>l', data.read(4))[0]
            data_IP = data.read(len_IP)
            sec2_fields = struct.unpack('>l', data.read(4))[0]

            sec_two.append(['URL', data_URL])
            sec_two.append(['IP', data_IP])
            for i in range(0, sec2_fields):
                len_field = struct.unpack('>h', data.read(2))[0]
                field = data.read(len_field)
                len_value = struct.unpack('>h', data.read(2))[0]
                value = data.read(len_value)
                sec_two.append([field, value])
            return sec_two

        def sec2_parse_602():
            """Parse Section Two from 6.02 files.

            Section two contains all download history data. However, this version
            does not store IP addresses.
            """
            sec_two = []
            data.seek(32)
            len_URL = struct.unpack('b', data.read(1))[0]
            data_URL = data.read(len_URL)
            # keep those 2 unused variables
            namespace_len = struct.unpack('>h', data.read(2))[0]
            sec2_fields = struct.unpack('>l', data.read(4))[0]
            sec_two.append(['URL', data_URL])

            for i in range(0, sec2_fields):
                len_field = struct.unpack('>h', data.read(2))[0]
                field = data.read(len_field)
                len_value = struct.unpack('>h', data.read(2))[0]
                value = data.read(len_value)
                sec_two.append([field, value])

            return sec_two

        def sec3_parse():
            """Parse Section three of the file.

            Section three contains a copy of the JAR manifest data.
            """
            sec_three = []
            data.seek(128 + sec2_len)
            sec3_data = data.read(sec3_len)

            if sec3_data[0:3] == '\x1F\x8B\x08':  # Valid GZIP header
                sec3_unc = zlib.decompress(sec3_data, 15 + 32)  # Trick to force bitwindow size
                sec_split = sec3_unc.strip().split('\n')
                for line in sec_split:
                    k, v = line.split(':')
                    sec_three.append([k, v.replace('\x0d', '')])
            return sec_three

        def sec4_parse():
            """Parse Section four of the file.

            Section four contains Code Signer details
            Written from docs at:
            http://docs.oracle.com/javase/6/docs/platform/serialization/spec/protocol.html
            """

            # ToDo Export any found data blocks or objects
            sec_four = []
            unknowns = 0
            data.seek(128 + sec2_len + sec3_len)
            sec4_magic, sec4_ver = struct.unpack('>HH', data.read(4))
            if sec4_magic == 0xACED:  # Magic number for Java serialized data, version always appears to be 5
                while not data.tell() == file_size:  # If current offset isn't at end of file yet
                    if unknowns > 5:
                        return sec_four
                    sec4_type = struct.unpack('B', data.read(1))[0]
                    if sec4_type == 0x77:
                        block_len = struct.unpack('b', data.read(1))[0]
                        sec_four.append("Found Data Block of length {0}".format(block_len))
                    elif sec4_type == 0x73:  # Object
                        sec_four.append("Found Data Object")
                        continue
                    elif sec4_type == 0x72:  # Class Description
                        block_len = struct.unpack('>h', data.read(2))[0]
                        sec_four.append("Found Class Description of lenght {0}".format(block_len))
                    else:
                        unknowns += 1
            return sec_four

        super(IDX, self).run()
        if self.args is None:
            return

        if not __sessions__.is_set():
            self.log('error', "No open session")
            return

        # Main starts here
        data = open(__sessions__.current.file.path)
        file_size = __sessions__.current.file.size

        # Keep those 2 unused variables
        busy_byte = data.read(1)
        complete_byte = data.read(1)

        cache_ver = struct.unpack('>i', data.read(4))[0]
        if cache_ver not in (602, 603, 604, 605, 606):
            self.log('error', "Invalid IDX header found")
            return
        self.log('info', "IDX File Version {0}.{1}".format(cache_ver / 100, cache_ver - 600))
        # Different IDX cache versions have data in different offsets
        if cache_ver in [602, 603, 604, 605]:
            if cache_ver in [602, 603, 604]:
                data.seek(8)
            elif cache_ver == 605:
                data.seek(6)
            # Not used, keep
            is_shortcut_img = data.read(1)
            content_len = struct.unpack('>l', data.read(4))[0]
            last_modified_date = struct.unpack('>q', data.read(8))[0] / 1000
            expiration_date = struct.unpack('>q', data.read(8))[0] / 1000
            validation_date = struct.unpack('>q', data.read(8))[0] / 1000

            sec_one = []
            sec_one.append(['Content Length', content_len])
            sec_one.append(['Last Modified Date', time.strftime('%a, %d %b %Y %X GMT', time.gmtime(last_modified_date))])
            if expiration_date:
                sec_one.append(['Expiration Date', time.strftime('%a, %d %b %Y %X GMT', time.gmtime(expiration_date))])
            if validation_date:
                sec_one.append(['Validation Date', time.strftime('%a, %d %b %Y %X GMT', time.gmtime(validation_date))])

            if cache_ver == 602:
                sec2_len = 1
                sec3_len = 0
                sec4_len = 0
                sec5_len = 0
            elif cache_ver in [603, 604, 605]:
                # Not used, keep
                known_to_be_signed = data.read(1)

                sec2_len = struct.unpack('>i', data.read(4))[0]
                sec3_len = struct.unpack('>i', data.read(4))[0]
                sec4_len = struct.unpack('>i', data.read(4))[0]
                sec5_len = struct.unpack('>i', data.read(4))[0]

                blacklist_timestamp = struct.unpack('>q', data.read(8))[0] / 1000
                cert_expiration_date = struct.unpack('>q', data.read(8))[0] / 1000

                # Not used, keep
                class_verification_status = data.read(1)
                reduced_manifest_length = struct.unpack('>l', data.read(4))[0]

                sec_one.append(['Section 2 length', sec2_len])
                if sec3_len:
                    sec_one.append(['Section 3 length', sec3_len])
                if sec4_len:
                    sec_one.append(['Section 4 length', sec4_len])
                if sec5_len:
                    sec_one.append(['Section 5 length', sec5_len])
                if expiration_date:
                    sec_one.append(['Blacklist Expiration date', time.strftime('%a, %d %b %Y %X GMT', time.gmtime(blacklist_timestamp))])
                if cert_expiration_date:
                    sec_one.append(['Certificate Expiration date', time.strftime('%a, %d %b %Y %X GMT', time.gmtime(cert_expiration_date))])

        if sec2_len:
            if cache_ver == 602:
                sec_two = sec2_parse_602()
            else:
                sec_two = sec2_parse()
        if sec3_len:
            sec_three = sec3_parse()
        if sec4_len:
            sec_four = sec4_parse()

        header = ['Field', 'Value']
        self.log('', "")
        self.log('info', "Section One")
        self.log('table', dict(header=header, rows=sec_one))
        self.log('', "")
        self.log('info', "Section Two")
        self.log('table', dict(header=header, rows=sec_two))
        self.log('', "")
        self.log('info', "Section Three")
        self.log('table', dict(header=header, rows=sec_three))
        self.log('', "")
        self.log('info', "Section Four")
        for item in sec_four:
            self.log('item', item)
