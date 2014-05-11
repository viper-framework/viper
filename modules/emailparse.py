# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os
import re
import email
import getopt
import hashlib
import tempfile
import mimetypes

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __session__

# TODO: Should probably split the different parsing capabilities in
# separate options and have a --all to run them all.

class EmailParse(Module):
    cmd = 'email'
    description = 'Parse SMTP mail'
    authors = ['Kevin Breen', 'nex']

    def run(self):
        def usage():
            print("usage: email parse [-hs]")

        def help():
            usage()
            print("")
            print("Options:")
            print("\t--help (-h)\tShow this help message")
            print("\t--session (-s)\tSwitch session to the specified attachment")
        
        def string_clean(value):
            return re.sub('[\n\t\r]', '', value)
        
        try:
            opts, argv = getopt.getopt(self.args, 'hs:', ['help', 'session='])
        except getopt.GetoptError as e:
            print(e)
            return

        arg_session = 0

        for opt, value in opts:
            if opt in ('-h', '--help'):
                help()
                return
            elif opt in ('-s', '--session'):
                arg_session = int(value)

        if not __session__.is_set():
            print_error("No session opened")
            return

        email_handle = open(__session__.file.path)
        msg = email.message_from_file(email_handle)
        email_handle.close()

        if arg_session > 0:
            att_count = 0
            for part in msg.walk():
                if part.get_content_maintype() == 'multipart' or not part.get('Content-Disposition'):
                    continue

                att_count += 1
                if att_count == arg_session:
                    print_info("Switching session to {0}".format(part.get_filename()))
                    data = part.get_payload(decode=True)

                    if data:
                        tmp_path = os.path.join(tempfile.gettempdir(), part.get_filename())
                        with open(tmp_path, 'w') as tmp:
                            tmp.write(data)

                        __session__.set(tmp_path)
                        return

        # Envelope
        print_info("Email envelope:")
        rows = [
            ['Subject', msg.get("Subject")],
            ['To', msg.get("To")],
            ['From', msg.get("From")],
            ['Cc', msg.get("Cc")],
            ['Bcc', msg.get("Bcc")],
            ['Date', msg.get("Date")]
        ]
        print(table(header=['Key', 'Value'], rows=rows))
        
        # Headers
        rows = []
        for x in msg.keys():
            if x not in ['Subject', 'From', 'To', 'Date', 'Cc', 'Bcc', 'DKIM-Signature']:
                rows.append([x, string_clean(msg.get(x))])

        print_info("Email headers:")
        rows = sorted(rows, key=lambda entry: entry[0])
        # TODO: need to figure out how to fix the formatting of headers'
        # values, there seems to be escape sequences or other crap that mess
        # up the tables.
        print(table(header=['Key', 'Value'], rows=rows))
        
        # Attachments
        att_count = 0
        rows = []
        links = []

        # Walk through email parts to extract links and attachments.
        for part in msg.walk():
            if part.get_content_maintype() == 'multipart':
                continue

            if part.get_content_type() in ('text/plain', 'text/html'):
                part_content = part.get_payload(decode=True)
                for link in re.findall(r'(https?://\S+)', part_content):
                    if link not in links:
                        links.append(link)

            if not part.get('Content-Disposition'):
                # These are not attachemnts.
                continue

            att_file_name = part.get_filename()
            att_size = len(part_content)            
            if not att_file_name:
                continue

            att_data = part.get_payload(decode=True)
            att_md5 = hashlib.md5(att_data).hexdigest()
            att_count += 1
            rows.append([att_count, att_file_name, part.get_content_type(), att_size, att_md5])

        print_info("Email attachments (total: {0}):".format(att_count))
        if att_count > 0:
            print(table(header=['ID', 'FileName', 'Content Type', 'File Size', 'MD5'], rows=rows))
        
        print_info("Email links:")
        for link in links:
            print_item(link)
