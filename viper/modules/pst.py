# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os
import datetime
import tempfile
import subprocess
import email
import hashlib
import shutil

from viper.common.abstracts import Module
from viper.core.session import __sessions__
from viper.core.project import __project__
from viper.common.objects import File
from viper.core.storage import store_sample
from viper.core.database import Database
from viper.common.utils import string_clean

class PST(Module):
    cmd = 'pst'
    description = 'Process PST Files for Attachment'
    authors = ['Kevin Breen']

    def __init__(self):
        super(PST, self).__init__()
        self.parser.add_argument('-p', '--proj', action='store_true', default=False, help='Create a New Project')
        self.parser.add_argument('-o', '--output', metavar='path', help='PST Export Path')
        self.parser.add_argument('-k', '--keep', action='store_true', default=False, help='Keep Exported PST Files')
    
    def parse_pst(self, save_path, pst_path):
        self.log('info', "Processing PST")
        subprocess.call('pffexport -t {0} {1} > /tmp/report.txt'.format(save_path, pst_path), shell=True)
        counter = 0
        for root, dirs, files in os.walk('{0}.export'.format(save_path)):
            for name in dirs:
                full_path = os.path.join(root, name)
                if name.startswith('Message'):
                    self.parse_message(full_path)
                    counter += 1
        return counter

    def parse_message(self, message_folder):
        db = Database()
        email_header = os.path.join(message_folder, 'InternetHeaders.txt')
        email_body = os.path.join(message_folder, 'Message.txt')
        
        envelope = headers = email_text = ''
        if os.path.exists(email_header):
            envelope, headers = self.email_headers(email_header)
        if os.path.exists(email_body):
            email_text = open(email_body, 'rb').read()
        
        tags = 'pst, {0}'.format(message_folder)
        if os.path.exists(os.path.join(message_folder, 'Attachments')):
            for filename in os.listdir(os.path.join(message_folder, 'Attachments')):
                if os.path.isfile(os.path.join(message_folder, 'Attachments', filename)):
                    obj = File(os.path.join(message_folder, 'Attachments', filename))
                    sha256 = hashlib.sha256(open(os.path.join(message_folder, 'Attachments', filename), 'rb').read()).hexdigest()
                    new_path = store_sample(obj)
                    if new_path:
                        # Add file to the database.
                        db.add(obj=obj, tags=tags)
                    # Add Email Details as a Note
                    # To handle duplicates we use multiple notes
                    headers_body = 'Envelope: \n{0}\nHeaders: \n{1}\n'.format(envelope, headers)
                    db.add_note(sha256, 'Headers', headers_body)
                    
                    # Add a note with email body
                    db.add_note(sha256, 'Email Body', string_clean(email_text))

    def email_headers(self, email_header):
        # If it came from outlook we may need to trim some lines
        new_mail = open(email_header).read()
        if 'Version 2.0\x0d\x0a' in new_mail:
            new_mail = new_mail.split('Version 2.0\x0d\x0a', 1)[1]
        # Leaving us an RFC compliant email to parse
        msg = email.message_from_string(new_mail)
        # Envelope
        envelope = [
                    string_clean(msg.get("Subject")),
                    string_clean(msg.get("To")),
                    string_clean(msg.get("From")),
                    string_clean(msg.get("Cc")),
                    string_clean( msg.get("Bcc")),
                    string_clean(msg.get("Date"))
                   ]
        # headers
        headers = []
        for x in msg.keys():
            if x not in ['Subject', 'From', 'To', 'Date', 'Cc', 'Bcc']:
                headers.append([x, msg.get(x)])
        headers = sorted(headers, key=lambda entry: entry[0])
        return envelope, headers
        
        
    def run(self):
        super(PST, self).run()
        pst_path = __sessions__.current.file.path
        pff_test = subprocess.call('pffexport -V', shell=True)
        if pff_test == 127:
            self.log('error', "pffexport not install. Try: 'sudo apt-get install pff-tools'")
            return

        new_proj = self.args.proj
        save_path = self.args.output
            
        if new_proj:
            self.log('info', "Creating New Project")
            project_name = str(datetime.date.today())
            __project__.open('pst_{0}'.format(project_name))

        if save_path:
            save_path = self.args.output
        else:
            save_path = tempfile.mkdtemp()

        self.log('info', "Temp Dir created at {0}".format(save_path))
        
        self.log('info', "Processing Attachments, this might take a while...")
        counter = self.parse_pst(save_path, pst_path)
        self.log('success', "Stored {0} Email attachments".format(counter))
        
        if not self.args.keep:
            try:
                shutil.rmtree('{0}.export'.format(save_path))
                shutil.rmtree(save_path)
                self.log('info', "Removing Temp Dir")
            except OSError as e:
                self.log('error', "Unable to delete tmpdir: {0}".format(e))
        
        
        
        
        
        
