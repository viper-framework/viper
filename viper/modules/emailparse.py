# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import sys
import os
import re
import email
import hashlib
import tempfile
import olefile

from viper.common.abstracts import Module
from viper.core.session import __sessions__

from io import open


class EmailParse(Module):
    cmd = 'email'
    description = 'Parse eml and msg email files'
    authors = ['Kevin Breen', 'nex']

    def __init__(self):
        super(EmailParse, self).__init__()
        self.parser.add_argument('-e', '--envelope', action='store_true', help='Show the email envelope')
        self.parser.add_argument('-f', '--attach', action='store_true', help='Show Attachment information')
        self.parser.add_argument('-r', '--header', action='store_true', help='Show email Header information')
        self.parser.add_argument('-t', '--trace', action='store_true', help='Show email path via Received headers')
        self.parser.add_argument('-T', '--traceall', action='store_true',
                                 help='Show email path via verbose Received headers')
        self.parser.add_argument('-s', '--spoofcheck', action='store_true', help='Test email for possible spoofing')
        self.parser.add_argument('-a', '--all', action='store_true', help='Run all the options')
        self.parser.add_argument('-o', '--open', type=int, help='Switch session to the specified attachment')

    def run(self, *args):

        def string_clean(value):
            if value:
                if isinstance(value, bytes):
                    if sys.version_info < (3, 4):
                        value = value.decode('utf-8', 'ignore')
                    else:
                        value = value.decode('utf-8', 'backslashreplace')
                elif isinstance(value, email.header.Header):
                    value = str(value)
                return re.sub('[\n\t\r]', '', str(value))
            return ""

        def parse_ole_msg(ole):
            email_h = None
            stream_dirs = ole.listdir()
            for stream in stream_dirs:
                # get stream that contains the email header
                if stream[0].startswith('__substg1.0_007D'):
                    email_h = ole.openstream(stream).read()
                    if stream[0].endswith('001F'):  # Unicode probably needs something better than just stripping \x00
                        email_h = email_h.replace(b'\x00', b'')
            # If it came from outlook we may need to trim some lines
            try:
                email_h = email_h.split(b'Version 2.0\x0d\x0a', 1)[1]
            except Exception:
                pass

            if not email_h:
                self.log('warning', 'This OLE file is not an email.')
                return None
            # Leaving us an RFC compliant email to parse
            if isinstance(email_h, str):
                # Python2 madness
                msg = email.message_from_string(email_h)
            else:
                msg = email.message_from_bytes(email_h)
            return msg

        def parse_ole_attachments(ole):
            # FIXME: Never used
            # Hard part now, each part of the attachment is in a seperate stream
            # need to get a unique stream id for each att
            # its in the streamname as an 8 digit number.
            header = ['#', 'Size', 'MD5', 'Filename', 'MimeType']
            rows = []
            for i in range(20):  # arbitrary count of emails. i dont expecet this many
                stream_number = str(i).zfill(8)
                stream_name = '__attach_version1.0_#' + stream_number
                # Unicode
                try:
                    att_filename = ole.openstream(stream_name + '/__substg1.0_3704001F').read().decode()
                    att_mime = ole.openstream(stream_name + '/__substg1.0_370E001F').read().decode()
                    att_data = ole.openstream(stream_name + '/__substg1.0_37010102').read()
                    att_size = len(att_data)
                    att_md5 = hashlib.md5(att_data).hexdigest()
                    rows.append([i, att_size, att_md5, att_filename, att_mime])
                except Exception:
                    pass
                # ASCII
                try:
                    att_filename = ole.openstream(stream_name + '/__substg1.0_3704001E').read().decode()
                    att_mime = ole.openstream(stream_name + '/__substg1.0_370E001E').read().decode()
                    att_data = ole.openstream(stream_name + '/__substg1.0_37010102').read()
                    att_size = len(att_data)
                    att_md5 = hashlib.md5(att_data).hexdigest()
                    rows.append([i, att_size, att_md5, att_filename, att_mime])
                except Exception:
                    pass
            self.log('table', dict(header=header, rows=rows))

        def att_session(att_id, msg, ole_flag):
            att_count = 0
            if ole_flag:
                ole = msg
                # Hard part now, each part of the attachment is in a seperate stream

                # need to get a unique stream id for each att
                # its in the streamname as an 8 digit number.
                for i in range(20):  # arbitrary count of emails. i dont expecet this many
                    stream_number = str(i).zfill(8)
                    stream_name = '__attach_version1.0_#' + stream_number
                    # Unicode
                    try:
                        att_filename = ole.openstream(stream_name + '/__substg1.0_3704001F').read()
                        att_filename = att_filename.replace(b'\x00', b'').decode()
                        att_data = ole.openstream(stream_name + '/__substg1.0_37010102').read()
                    except Exception:
                        pass
                    # ASCII
                    try:
                        att_filename = ole.openstream(stream_name + '/__substg1.0_3704001E').read().decode()
                        att_data = ole.openstream(stream_name + '/__substg1.0_37010102').read()
                    except Exception:
                        pass
                    if i == att_id:
                        self.log('info', "Switching session to {0}".format(att_filename))
                        tmp_path = os.path.join(tempfile.gettempdir(), att_filename)
                        with open(tmp_path, 'wb') as tmp:
                            tmp.write(att_data)
                        __sessions__.new(tmp_path)
                        return

            else:
                for part in msg.walk():
                    if part.get_content_type() == 'message/rfc822':
                        rfc822 = True
                    else:
                        rfc822 = False

                    if part.get_content_maintype() == 'multipart' or not part.get('Content-Disposition') and not rfc822:
                        continue

                    att_count += 1
                    if att_count == att_id:
                        if rfc822:
                            data = part.as_string()
                            m = re.match("Content-Type: message/rfc822\r?\n\r?\n(.*)", data, flags=re.S)
                            if not m:
                                self.log('error', "Could not extract RFC822 formatted message")
                                return
                            data = m.group(1)
                            att_size = len(data)
                            filename = "rfc822msg_{0}.eml".format(att_size)
                        else:
                            data = part.get_payload(decode=True)
                            filename = part.get_filename()

                        self.log('info', "Switching session to {0}".format(filename))

                        if data:
                            tmp_path = os.path.join(tempfile.gettempdir(), filename)
                            with open(tmp_path, 'wb') as tmp:
                                tmp.write(data)
                            __sessions__.new(tmp_path)
                            return

        def email_envelope(msg):
            # Envelope
            self.log('info', "Email envelope:")
            rows = [
                ['Subject', msg.get("Subject")],
                ['To', msg.get("To")],
                ['From', msg.get("From")],
                ['Cc', msg.get("Cc")],
                ['Bcc', msg.get("Bcc")],
                ['Date', msg.get("Date")]
            ]
            self.log('table', dict(header=['Key', 'Value'], rows=rows))
            return

        def email_header(msg):
            # Headers
            rows = []
            for x in msg.keys():
                # Adding Received to ignore list. this has to be handeled separately if there are more then one line
                if x not in ['Subject', 'From', 'To', 'Date', 'Cc', 'Bcc', 'DKIM-Signature', 'Received']:
                    rows.append([x, string_clean(msg.get(x))])
            for x in msg.get_all('Received'):
                rows.append(['Received', string_clean(x)])
            self.log('info', "Email headers:")
            rows = sorted(rows, key=lambda entry: entry[0])
            self.log('table', dict(header=['Key', 'Value'], rows=rows))
            return

        def email_trace(msg, verbose):
            rows = []
            if verbose:
                fields = ['from', 'by', 'with', 'id', 'for', 'timestamp']
            else:
                fields = ['from', 'by', 'timestamp']
            for x in msg.get_all('Received'):
                x = string_clean(x)
                cre = re.compile("""
                    (?: from \s+ (?P<from>.*?) (?=by|with|id|ID|for|;|$) )?
                    (?: by \s+ (?P<by>.*?) (?=with|id|ID|for|;|$) )?
                    (?: with \s+ (?P<with>.*?) (?=id|ID|for|;|$) )?
                    (?: (id|ID) \s+ (?P<id>.*?) (?=for|;|$) )?
                    (?: for \s+ (?P<for>.*?) (?=;|$) )?
                    (?: \s* ; \s* (?P<timestamp>.*) )?
                    """, flags=re.X | re.I)
                m = cre.search(x)
                if not m:
                    self.log('error', "Received header regex didn't match")
                    return
                t = []
                for groupname in fields:
                    t.append(string_clean(m.group(groupname)))
                rows.insert(0, t)
            self.log('info', "Email path trace:")
            self.log('table', dict(header=fields, rows=rows))
            return

        def email_spoofcheck(msg, dnsenabled):
            self.log('info', "Email spoof check:")

            # test 1: check if From address is the same as Sender, Reply-To, and Return-Path
            rows = [
                ['Sender', string_clean(msg.get("Sender"))],
                ['From', string_clean(msg.get("From"))],
                ['Reply-To', string_clean(msg.get("Reply-To"))],
                ['Return-Path', string_clean(msg.get("Return-Path"))]
            ]
            self.log('table', dict(header=['Key', 'Value'], rows=rows))
            addr = {
                'Sender': email.utils.parseaddr(string_clean(msg.get("Sender")))[1],
                'From': email.utils.parseaddr(string_clean(msg.get("From")))[1],
                'Reply-To': email.utils.parseaddr(string_clean(msg.get("Reply-To")))[1],
                'Return-Path': email.utils.parseaddr(string_clean(msg.get("Return-Path")))[1]
            }
            if (addr['From'] == ''):
                self.log('error', "No From address!")
                return
            elif addr['Sender'] and (addr['From'] != addr['Sender']):
                self.log('warning', "Email FAILED: From address different than Sender")
            elif addr['Reply-To'] and (addr['From'] != addr['Reply-To']):
                self.log('warning', "Email FAILED: From address different than Reply-To")
            elif addr['Return-Path'] and (addr['From'] != addr['Return-Path']):
                self.log('warning', "Email FAILED: From address different than Return-Path")
            else:
                self.log('success', "Email PASSED: From address the same as Sender, Reply-To, and Return-Path")

            # test 2: check to see if first Received: by domain matches sender MX domain
            if not dnsenabled:
                self.log('info', "Unable to run Received by / sender check without dnspython available")
            else:
                r = msg.get_all('Received')[-1]
                m = re.search("by\s+(\S*?)(?:\s+\(.*?\))?\s+with", r)
                if not m:
                    self.log('error', "Received header regex didn't match")
                    return
                byname = m.group(1)
                # this can be either a name or an IP
                m = re.search("(\w+\.\w+|\d+\.\d+\.\d+\.\d+)$", byname)
                if not m:
                    self.log('error', "Could not find domain or IP in Received by field")
                    return
                bydomain = m.group(1)
                domains = [['Received by', bydomain]]
                # if it's an IP, do the reverse lookup
                m = re.search("\.\d+$", bydomain)
                if m:
                    bydomain = str(dns.reversename.from_address(bydomain)).strip('.')
                    domains.append(['Received by reverse lookup', bydomain])
                # if the email has a Sender header, use that
                if (addr['Sender'] != ""):
                    m = re.search("(\w+\.\w+)$", addr['Sender'])
                    if not m:
                        self.log('error', "Sender header regex didn't match")
                        return
                    fromdomain = m.group(1)
                    domains.append(['Sender', fromdomain])
                # otherwise, use the From header
                else:
                    m = re.search("(\w+\.\w+)$", addr['From'])
                    if not m:
                        self.log('error', "From header regex didn't match")
                        return
                    fromdomain = m.group(1)
                    domains.append(['From', fromdomain])

                bymatch = False
                try:
                    mx = dns.resolver.query(fromdomain, 'MX')
                    if mx:
                        for rdata in mx:
                            m = re.search("(\w+\.\w+).$", str(rdata.exchange))
                            if not m:
                                self.log('error', "MX domain regex didn't match")
                                continue
                            domains.append(['MX for ' + fromdomain, m.group(1)])
                            if bydomain == m.group(1):
                                bymatch = True
                    self.log('table', dict(header=['Key', 'Value'], rows=domains))
                except Exception:
                    domains.append(['MX for ' + fromdomain, "not registered in DNS"])
                    self.log('table', dict(header=['Key', 'Value'], rows=domains))
                if bymatch:
                    self.log('success', "Email PASSED: Received by domain found in Sender/From MX domains")
                else:
                    self.log('warning', "Email FAILED: Could not match Received by domain to Sender/From MX")

            # test 3: look at SPF records
            rspf = []
            results = set()
            allspf = msg.get_all('Received-SPF')
            if not allspf:
                return
            for spf in allspf:
                # self.log('info', string_clean(spf))
                m = re.search("\s*(\w+)\s+\((.*?):\s*(.*?)\)\s+(.*);", string_clean(spf))
                if not m:
                    self.log('error', "Received-SPF regex didn't match")
                    return
                rspf.append([m.group(2), m.group(1), m.group(3), m.group(4)])
                results = results | {m.group(1)}
            self.log('table', dict(header=['Domain', 'Action', 'Info', 'Additional'], rows=rspf))
            if results & {'fail', 'softfail'}:
                self.log('warning', "Email FAILED: Found fail or softfail SPF results")
            elif results & {'none', 'neutral'}:
                self.log('warning', "Email NEUTRAL: Found none or neutral SPF results")
            elif results & {'permerror', 'temperror'}:
                self.log('warning', "Email NEUTRAL: Found error condition")
            elif results & {'pass'}:
                self.log('success', "Email PASSED: Found SPF pass result")

            return

        def email_attachments(msg, ole_flag):
            # Attachments
            att_count = 0
            rows = []
            links = []
            if ole_flag:
                ole = msg
                # Hard part now, each part of the attachment is in a seperate stream

                # need to get a unique stream id for each att
                # its in the streamname as an 8 digit number.
                for i in range(20):  # arbitrary count of emails. i dont expecet this many
                    stream_number = str(i).zfill(8)
                    stream_name = '__attach_version1.0_#' + stream_number
                    # Unicode
                    try:
                        att_filename = ole.openstream(stream_name + '/__substg1.0_3704001F').read()
                        att_filename = att_filename.replace(b'\x00', b'').decode()
                        att_mime = ole.openstream(stream_name + '/__substg1.0_370E001F').read()
                        att_mime = att_mime.replace(b'\x00', b'').decode()
                        att_data = ole.openstream(stream_name + '/__substg1.0_37010102').read()
                        att_size = len(att_data)
                        att_md5 = hashlib.md5(att_data).hexdigest()
                        rows.append([i, att_filename, att_mime, att_size, att_md5])
                        att_count += 1
                    except Exception:
                        pass
                    # ASCII
                    try:
                        att_filename = ole.openstream(stream_name + '/__substg1.0_3704001E').read().decode()
                        att_mime = ole.openstream(stream_name + '/__substg1.0_370E001E').read().decode()
                        att_data = ole.openstream(stream_name + '/__substg1.0_37010102').read()
                        att_size = len(att_data)
                        att_md5 = hashlib.md5(att_data).hexdigest()
                        rows.append([i, att_filename, att_mime, att_size, att_md5])
                        att_count += 1
                    except Exception:
                        pass

            else:
                # Walk through email string.
                for part in msg.walk():
                    content_type = part.get_content_type()

                    if content_type == 'multipart':
                        continue

                    if content_type in ('text/plain', 'text/html'):
                        part_content = part.get_payload(decode=True)
                        for link in re.findall(b'(https?://[^"<>\s]+)', part_content):
                            if link not in links:
                                links.append(link.decode())

                    if content_type == 'message/rfc822':
                        part_content = part.as_string()
                        m = re.match("Content-Type: message/rfc822\r?\n\r?\n(.*)", part_content, flags=re.S)
                        if not m:
                            self.log('error', "Could not extract RFC822 formatted message")
                            return
                        part_content = m.group(1)
                        att_size = len(part_content)
                        att_file_name = "rfc822msg_{0}.eml".format(att_size)
                        att_md5 = hashlib.md5(part_content).hexdigest()
                        att_count += 1
                        rows.append([att_count, att_file_name, content_type, att_size, att_md5])
                        continue

                    if not part.get('Content-Disposition'):
                        # These are not attachments.
                        continue

                    att_file_name = part.get_filename()
                    att_size = len(part_content)

                    if not att_file_name:
                        continue

                    att_data = part.get_payload(decode=True)
                    att_md5 = hashlib.md5(att_data).hexdigest()
                    att_count += 1
                    rows.append([att_count, att_file_name, part.get_content_type(), att_size, att_md5])

            self.log('info', "Email attachments (total: {0}):".format(att_count))
            if att_count > 0:
                self.log('table', dict(header=['ID', 'FileName', 'Content Type', 'File Size', 'MD5'], rows=rows))

            self.log('info', "Email links:")
            for link in links:
                self.log('item', link)
            return

        super(EmailParse, self).run(*args)
        if self.args is None:
            return

        # Start Here
        if not __sessions__.is_set():
            self.log('error', "No open session")
            return

        # see if we can load the dns library for MX lookup spoof detecton
        try:
            import dns.resolver
            import dns.reversename
            dnsenabled = True
        except ImportError:
            dnsenabled = False

        # Try to open as an ole msg, if not treat as email string
        try:
            ole = olefile.OleFileIO(__sessions__.current.file.data)
            msg = parse_ole_msg(ole)
            if not msg:
                return
            ole_flag = True
        except Exception:
            ole_flag = False
            if sys.version_info < (3, 0):
                msg = email.message_from_string(__sessions__.current.file.data)
            else:
                msg = email.message_from_bytes(__sessions__.current.file.data)

        if self.args.open is not None:
            if ole_flag:
                msg = ole
            att_session(self.args.open, msg, ole_flag)
        elif self.args.envelope:
            email_envelope(msg)
        elif self.args.attach:
            if ole_flag:
                msg = ole
            email_attachments(msg, ole_flag)
        elif self.args.header:
            email_header(msg)
        elif self.args.trace:
            email_trace(msg, False)
        elif self.args.traceall:
            email_trace(msg, True)
        elif self.args.spoofcheck:
            email_spoofcheck(msg, dnsenabled)
        elif self.args.all:
            email_envelope(msg)
            email_header(msg)
            email_trace(msg, True)
            email_spoofcheck(msg, dnsenabled)
            if ole_flag:
                msg = ole
            email_attachments(msg, ole_flag)
        else:
            self.log('error', 'At least one of the parameters is required')
            self.usage()
