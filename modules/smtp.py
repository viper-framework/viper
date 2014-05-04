# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.


import os
import getopt
import email
import mimetypes
import re
import hashlib


from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __session__


class SMTPParse(Module):
    cmd = 'smtp'
    description = 'Parse SMTP Stream'

    def run(self):
        def usage():
            print("usage: smtp parse [-hs]")

        def help():
            usage()
            print("")
            print("Options:")
            print("\t--help (-h)\tShow this help message")
            print("\t--session (-s)\tSwitch Session to [Att ID]")

        try:
            opts, argv = getopt.getopt(self.args, 'hs:', ['help', 'session='])
        except getopt.GetoptError as e:
            print(e)
            return
        session = 0
        for opt, value in opts:
            if opt in ('-h', '--help'):
                help()
                return
            elif opt in ('-s', '--session'):
                session = int(value)

        emailString = open(__session__.file.path)
        msg= email.message_from_file(emailString)
        emailString.close()
        if session > 0:
            attCount = 0
            for part in msg.walk():
                if part.get_content_maintype() == 'multipart':
                    continue
                if part.get('Content-Disposition') is None:
                    # These are not attachemnts
                    continue
                attCount += 1
                if attCount == session:
                    print_info("Switching Session to {0}".format(part.get_filename()))
                    data = part.get_payload(decode=True)
                    if data:
                        tempName = os.path.join('/tmp', part.get_filename())
                        with open(tempName, 'w') as temp:
                            temp.write(data)
                        __session__.set(tempName)
                        return
                        
        # Headers
        rows = []
        for x in msg.keys():
            if x not in ['Subject', 'From', 'To', 'Date', 'Cc', 'Bcc', 'DKIM-Signature']:
                rows.append([x, msg.get(x)])
        rows = sorted(rows, key=lambda entry: entry[0])
        print_info("Email Header:")
        print(table(header=['Key', 'Value'], rows=rows))
        
        # Envelope
        rows = []
        rows.append(['Subject', msg.get("Subject")])
        rows.append(['To', msg.get("To")])
        rows.append(['From', msg.get("From")])
        rows.append(['Cc', msg.get("Cc")])
        rows.append(['Bcc', msg.get("Bcc")])
        rows.append(['Date', msg.get("Date")])
        print_info("Email Envelope:")
        print(table(header=['Key', 'Value'], rows=rows))
        
        # Attachments
        attCount = 0
        rows = []
        textLinks = []
        htmlLinks = []
        for part in msg.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            if part.get_content_type() == 'text/plain':
                contents = part.get_payload(decode=True)
                # This is the email body
                textLinks = re.findall(r'(https?://\S+)', contents)
            if part.get_content_type() == 'text/html':
                contents = part.get_payload(decode=True)
                # HTML Formatted Body
                # Might try BeautifulSoup to extract here
                htmlLinks = re.findall(r'(https?://\S+)', contents)
            if part.get('Content-Disposition') is None:
                # These are not attachemnts
                continue
            AttFileName = part.get_filename()
            AttSize = len(contents)            
            if AttFileName == None:
                ext = mimetypes.guess_extension(part.get_content_type())
                if not ext:
                    ext = '.bin'
                filename = 'part-{0}{1}'.format(attCount, ext)
            attData = part.get_payload(decode=True)
            attMd5 = hashlib.md5(attData).hexdigest()
            attCount += 1
            rows.append([attCount, AttFileName, part.get_content_type(), AttSize, attMd5])

        print_info("Email Attachments - Count = {0}:".format(attCount))
        print(table(header=['ID', 'FileName', 'ContentType', 'FileSize', 'MD5'], rows=rows))
        
        # Links in the Email Body
        emailLinks = []
        for link in textLinks:
            print link
            emailLinks.append([link])
        for link in htmlLinks:
            emailLinks.append([link])
        print_info("Email Links:")
        print(table(header=['url'], rows=emailLinks))



