# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os
import re
import email
import getopt
import hashlib
import tempfile
import mimetypes
import OleFileIO_PL

from viper.common.out import *
from viper.common.abstracts import Module
from viper.core.session import __sessions__

class EmailParse(Module):
    cmd = 'email'
    description = 'Parse eml and msg email files'
    authors = ['Kevin Breen', 'nex']

    def run(self):
        def usage():
            print("usage: email [-hefro]")

        def help():
            usage()
            print("")
            print("Options:")
            print("\t--help (-h)\tShow this help message")
            print("\t--envelope (-e)\tShow the email envelope")
            print("\t--attach (-f)\tShow Attachment information")
            print("\t--header (-r)\tShow email Header information")
            print("\t--all (-a)\tRun all the options")
            print("\t--open (-o)\tSwitch session to the specified attachment")
        
        def string_clean(value):
            return re.sub('[\n\t\r]', '', value)

        def parse_ole_msg(ole):
            stream_dirs = ole.listdir()
            for stream in stream_dirs:
                #get stream that contains the email header
                if stream[0].startswith('__substg1.0_007D'):
                    email_header = ole.openstream(stream).read()
                    if stream[0].endswith('001F'): # Unicode probably needs something better than just stripping \x00
                        email_header = email_header.replace('\x00', '')
            # If it came from outlook we may need to trim some lines
            try:
                email_header = email_header.split('Version 2.0\x0d\x0a', 1)[1]
            except:
                pass
                
            # Leaving us an RFC compliant email to parse
            msg = email.message_from_string(email_header)
            return msg

        def parse_ole_attachments(ole):
            # Hard part now, each part of the attachment is in a seperate stream

            # need to get a unique stream id for each att
            # its in the streamname as an 8 digit number. 
            for i in range(20): # arbitrary count of emails. i dont expecet this many
                stream_number = str(i).zfill(8)
                stream_name = '__attach_version1.0_#'+stream_number
                #Unicode
                try:
                    att_filename = ole.openstream(stream_name+'/__substg1.0_3704001F').read()
                    att_mime = ole.openstream(stream_name+'/__substg1.0_370E001F').read()
                    att_data = ole.openstream(stream_name+'/__substg1.0_37010102').read()
                    att_size = len(att_data)
                    att_md5 = hashlib.md5(att_data).hexdigest()
                    print i, att_size, att_md5, att_filename, att_mime
                except:
                    pass
                # ASCII
                try:
                    att_filename = ole.openstream(stream_name+'/__substg1.0_3704001E').read()
                    att_mime = ole.openstream(stream_name+'/__substg1.0_370E001E').read()
                    att_data = ole.openstream(stream_name+'/__substg1.0_37010102').read()
                    att_size = len(att_data)
                    att_md5 = hashlib.md5(att_data).hexdigest()
                    print i, att_size, att_md5, att_filename, att_mime
                except:
                    pass

        def att_session(att_id, msg, ole_flag):
            att_count = 0
            if ole_flag:
                ole = msg
                # Hard part now, each part of the attachment is in a seperate stream

                # need to get a unique stream id for each att
                # its in the streamname as an 8 digit number. 
                for i in range(20): # arbitrary count of emails. i dont expecet this many
                    stream_number = str(i).zfill(8)
                    stream_name = '__attach_version1.0_#'+stream_number
                    #Unicode
                    try:
                        att_filename = ole.openstream(stream_name+'/__substg1.0_3704001F').read()
                        att_filename = att_filename.replace('\x00', '')
                        att_data = ole.openstream(stream_name+'/__substg1.0_37010102').read()
                    except:
                        pass
                    # ASCII
                    try:
                        att_filename = ole.openstream(stream_name+'/__substg1.0_3704001E').read()
                        att_data = ole.openstream(stream_name+'/__substg1.0_37010102').read()
                    except:
                        pass
                    if i == att_id:
                        print_info("Switching session to {0}".format(att_filename))
                        tmp_path = os.path.join(tempfile.gettempdir(), att_filename)
                        with open(tmp_path, 'w') as tmp:
                            tmp.write(att_data)
                        __sessions__.new(tmp_path)
                        return

            else:
                for part in msg.walk():
                    if part.get_content_maintype() == 'multipart' or not part.get('Content-Disposition'):
                        continue

                    att_count += 1
                    if att_count == att_id:
                        print_info("Switching session to {0}".format(part.get_filename()))
                        data = part.get_payload(decode=True)

                        if data:
                            tmp_path = os.path.join(tempfile.gettempdir(), part.get_filename())
                            with open(tmp_path, 'w') as tmp:
                                tmp.write(data)

                            __sessions__.new(tmp_path)
                            return

        def email_envelope(msg):
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
            return

        def email_header(msg):
            # Headers
            rows = []
            for x in msg.keys():
                if x not in ['Subject', 'From', 'To', 'Date', 'Cc', 'Bcc', 'DKIM-Signature']:
                    rows.append([x, string_clean(msg.get(x))])
            print_info("Email headers:")
            rows = sorted(rows, key=lambda entry: entry[0])
            print(table(header=['Key', 'Value'], rows=rows))
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
                for i in range(20): # arbitrary count of emails. i dont expecet this many
                    stream_number = str(i).zfill(8)
                    stream_name = '__attach_version1.0_#'+stream_number
                    #Unicode
                    try:
                        att_filename = ole.openstream(stream_name+'/__substg1.0_3704001F').read()
                        att_mime = ole.openstream(stream_name+'/__substg1.0_370E001F').read()
                        att_data = ole.openstream(stream_name+'/__substg1.0_37010102').read()
                        att_size = len(att_data)
                        att_md5 = hashlib.md5(att_data).hexdigest()
                        rows.append([i, att_filename, att_mime, att_size, att_md5])
                        att_count += 1
                    except:
                        pass
                    # ASCII
                    try:
                        att_filename = ole.openstream(stream_name+'/__substg1.0_3704001E').read()
                        att_mime = ole.openstream(stream_name+'/__substg1.0_370E001E').read()
                        att_data = ole.openstream(stream_name+'/__substg1.0_37010102').read()
                        att_size = len(att_data)
                        att_md5 = hashlib.md5(att_data).hexdigest()
                        rows.append([i, att_filename, att_mime, att_size, att_md5])
                        att_count += 1
                    except:
                        pass
                
                
            else:
                # Walk through email string.
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
            return
            
            
        # Start Here
        
        if not __sessions__.is_set():
            print_error("No session opened")
            return

        try:
            opts, argv = getopt.getopt(self.args, 'hefrao:', ['help', 'envelope', 'attach', 'header', 'all', 'open='])
        except getopt.GetoptError as e:
            print(e)
            return

        # Try to open as an ole msg, if not treat as email string
        try:
            ole = OleFileIO_PL.OleFileIO(__sessions__.current.file.path)
            ole_flag = True
        except:
            ole_flag = False
            email_handle = open(__sessions__.current.file.path)
            msg = email.message_from_file(email_handle)
            email_handle.close()
        
        for opt, value in opts:
            if opt in ('-h', '--help'):
                help()
                return
            elif opt in ('-o', '--open'):
                if ole_flag:
                    msg = ole
                att_session(int(value), msg, ole_flag)
                return
            elif opt in ('-e' '--envelope'):
                if ole_flag:
                    msg = parse_ole_msg(ole)
                email_envelope(msg)
                return
            elif opt in ('-f', '--attach'):
                if ole_flag:
                    msg = ole
                email_attachments(msg, ole_flag)
                return
            elif opt in ('-r','--header'):
                if ole_flag:
                    msg = parse_ole_msg(ole)
                email_header(msg)
                return
            elif opt in ('-a', '--all'):
                if ole_flag:
                    msg = parse_ole_msg(ole)
                email_envelope(msg)
                email_header(msg)
                if ole_flag:
                    msg = ole
                email_attachments(msg, ole_flag)
                return

        usage()
