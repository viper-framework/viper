# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import argparse
import textwrap
import os
import json

try:
    from pymisp import PyMISP, PyMISPError, MISPEvent, EncodeFull
    HAVE_PYMISP = True
except:
    HAVE_PYMISP = False

try:
    import requests
    HAVE_REQUESTS = True
except:
    HAVE_REQUESTS = False


from viper.common.abstracts import Module
from viper.core.database import Database
from viper.core.session import __sessions__
from viper.core.project import __project__
from viper.core.storage import get_sample_path
from viper.common.objects import MispEvent
from viper.common.constants import VIPER_ROOT
from viper.core.config import Config

cfg = Config()


class MISP(Module):
    cmd = 'misp'
    description = 'Upload and query IOCs to/from a MISP instance'
    authors = ['Raphaël Vinot']

    from .misp_methods import admin  # noqa
    from .misp_methods import create_event  # noqa
    from .misp_methods import download  # noqa
    from .misp_methods import check_hashes, _prepare_attributes, _populate  # noqa
    from .misp_methods import store, _get_local_events  # noqa
    from .misp_methods import tag  # noqa
    from .misp_methods import version  # noqa
    from .misp_methods import open_samples, _load_tmp_samples, _display_tmp_files, _clean_tmp_samples  # noqa
    from .misp_methods import add, add_hashes, _check_add, _change_event  # noqa

    def __init__(self):
        super(MISP, self).__init__()
        self.cur_path = __project__.get_path()
        self.parser.add_argument("--url", help='URL of the MISP instance')
        self.parser.add_argument("--off", action='store_true', help='Use offline (can only work on pre-downloaded events)')
        self.parser.add_argument("--on", action='store_true', help='Switch to online mode')
        self.parser.add_argument("-k", "--key", help='Your key on the MISP instance')
        self.parser.add_argument("-v", "--verify", action='store_false', help='Disable certificate verification (for self-signed)')
        subparsers = self.parser.add_subparsers(dest='subname')

        # ##### Upload sample to MISP #####
        parser_up = subparsers.add_parser('upload', help='Send malware sample to MISP.',
                                          formatter_class=argparse.RawDescriptionHelpFormatter,
                                          description=textwrap.dedent('''
                                            Distribution levels:
                                                * 0: Your organisation only
                                                * 1: This community only
                                                * 2: Connected communities
                                                * 3: All communities
                                                * 5: Inherit

                                            Sample categories:
                                                * 0: Payload delivery
                                                * 1: Artifacts dropped
                                                * 2: Payload installation
                                                * 3: External analysis

                                            Analysis levels:
                                                * 0: Initial
                                                * 1: Ongoing
                                                * 2: Completed

                                            Threat levels:
                                                * 0: High
                                                * 1: Medium
                                                * 2: Low
                                                * 3: Undefined
                                          '''))
        parser_up.add_argument("-e", "--event", type=int, help="Event ID to update. If None, and you're not connected to a MISP event a new one is created.")
        parser_up.add_argument("-d", "--distrib", type=int, choices=[0, 1, 2, 3, 5], help="Distribution of the attributes for the new event.")
        parser_up.add_argument("-s", "--sharing", type=int, help="Sharing group ID when distribution is set to 4.")
        parser_up.add_argument("-ids", action='store_true', help="Is eligible for automatically creating IDS signatures.")
        parser_up.add_argument("-c", "--categ", type=int, choices=[0, 1, 2, 3], default=1, help="Category of the samples.")
        parser_up.add_argument("-i", "--info", nargs='+', help="Event info field of a new event.")
        parser_up.add_argument("-o", "--comment", nargs='+', help="Comment associated to the sample.")
        parser_up.add_argument("-a", "--analysis", type=int, choices=[0, 1, 2], help="Analysis level a new event.")
        parser_up.add_argument("-t", "--threat", type=int, choices=[0, 1, 2, 3], help="Threat level of a new event.")

        # ##### Download samples from event #####
        parser_down = subparsers.add_parser('download', help='Download malware samples from MISP.')
        group = parser_down.add_mutually_exclusive_group()
        group.add_argument("-e", "--event", type=int, help="Download all the samples related to this event ID.")
        group.add_argument("-l", "--list", nargs='*', help="Download all the samples related to a list of events. Empty list to download all the samples of all the events stored in the current project.")  # noqa
        group.add_argument("--hash", help="Download the sample related to this hash (only MD5).")

        # ##### Search in MISP #####
        parser_search = subparsers.add_parser('search', help='Search in all the attributes.')
        parser_search.add_argument("query", nargs='*', help="String to search (if empty, search the hashes of the current file).")

        # ##### Check hashes on VT #####
        parser_checkhashes = subparsers.add_parser('check_hashes', help='Crosscheck hashes on VT.')
        parser_checkhashes.add_argument("event", nargs='?', default=None, type=int, help="Lookup all the hashes of an event on VT.")
        parser_checkhashes.add_argument("-p", "--populate", action='store_true', help="Automatically populate event with hashes found on VT.")

        # ##### Download Yara rules #####
        parser_checkhashes = subparsers.add_parser('yara', help='Get YARA rules of an event.')
        parser_checkhashes.add_argument("event", nargs='?', default=None, type=int, help="Download the yara rules of that event.")

        # ##### Get Events #####
        parser_pull = subparsers.add_parser('pull', help='Initialize the session with an existing MISP event.')
        parser_pull.add_argument("event", nargs='+', type=int, help="(List of) Event(s) ID.")

        # ##### Create an Event #####
        parser_create_event = subparsers.add_parser('create_event', help='Create a new event on MISP and initialize the session with it.',
                                                    formatter_class=argparse.RawDescriptionHelpFormatter,
                                                    description=textwrap.dedent('''
                                                      Distribution levels:
                                                          * 0: Your organisation only
                                                          * 1: This community only
                                                          * 2: Connected communities
                                                          * 3: All communities
                                                          * 4: Sharing group

                                                      Sharing Group:
                                                          * #: ID of sharing group

                                                      Analysis levels:
                                                          * 0: Initial
                                                          * 1: Ongoing
                                                          * 2: Completed

                                                      Threat levels:
                                                          * 0: High
                                                          * 1: Medium
                                                          * 2: Low
                                                          * 3: Undefined
                                                    '''))
        parser_create_event.add_argument("-d", "--distrib", type=int, choices=[0, 1, 2, 3, 4], help="Distribution of the attributes for the new event.")
        parser_create_event.add_argument("-s", "--sharing", type=int, help="Sharing group ID when distribution is set to 4.")
        parser_create_event.add_argument("-t", "--threat", type=int, choices=[0, 1, 2, 3], help="Threat level of a new event.")
        parser_create_event.add_argument("-a", "--analysis", type=int, choices=[0, 1, 2], help="Analysis level a new event.")
        parser_create_event.add_argument("-i", "--info", required=True, nargs='+', help="Event info field of a new event.")
        parser_create_event.add_argument("--date", help="Date of the event. (Default: today).")

        # ##### Add Hashes #####
        h = subparsers.add_parser("add_hashes", help="If no parameters, add all the hashes of the current session.")
        h.add_argument("-f", "--filename", help="Filename")
        h.add_argument("-m", "--md5", help="MD5")
        h.add_argument("-s", "--sha1", help="SHA1")
        h.add_argument("-a", "--sha256", help="SHA256")

        # ##### Add attributes #####
        parser_add = subparsers.add_parser('add', help='Add attributes to an existing MISP event.')
        subparsers_add = parser_add.add_subparsers(dest='add')
        # Hashes
        # Generic add
        temp_me = MISPEvent()
        for t in sorted(temp_me.types):
            sp = subparsers_add.add_parser(t, help="Add {} to the event.".format(t))
            sp.add_argument(t, nargs='+')

        # ##### Show attributes  #####
        subparsers.add_parser('show', help='Show attributes to an existing MISP event.')

        # ##### Open file #####
        o = subparsers.add_parser('open', help='Open a sample from the temp directory.')
        ox = o.add_mutually_exclusive_group(required=True)
        ox.add_argument("-l", "--list", action='store_true', help="List available files")
        ox.add_argument("-d", "--delete", help="Delete temporary files (use 'all' to remove all the local samples or an Event ID to only remove the associated samples)")
        ox.add_argument("sid", nargs='?', type=int, help='Sample ID to open (from the list option).')

        # ##### Publish an event #####
        subparsers.add_parser('publish', help='Publish an existing MISP event.')

        # ##### Show version #####
        subparsers.add_parser('version', help='Returns the version of the MISP instance.')

        # Store
        s = subparsers.add_parser('store', help='Store the current MISP event in the current project.')
        s.add_argument("-l", "--list", action='store_true', help="List stored MISP events")
        s.add_argument("-u", "--update", action='store_true', help="Update all stored MISP events")
        s.add_argument("-s", "--sync", action='store_true', help="Sync all MISP Events with the remote MISP instance")
        s.add_argument("-d", "--delete", type=int, help="Delete a stored MISP event")
        s.add_argument("-o", "--open", help="Open a stored MISP event")

        # Tags
        s = subparsers.add_parser('tag', help='Tag managment using MISP taxonomies.')
        s.add_argument("-l", "--list", action='store_true', help="List Existing taxonomies.")
        s.add_argument("-d", "--details", help="Display all values of a taxonomy.")
        s.add_argument("-s", "--search", help="Search all tags matching a value.")
        s.add_argument("-e", "--event", help="Add tag to the current event.")
        s.add_argument("-a", "--attribute", nargs='+', help="Add tag to an attribute of the current event. Syntax: <identifier for the attribute> <machinetag>")

        # Admin
        s = subparsers.add_parser('admin', help='Administration options.')
        admin_parser = s.add_subparsers(dest='admin')
        # Organisation
        org = admin_parser.add_parser('org', help="Organisation managment.")
        subparsers_org = org.add_subparsers(dest='org')
        # Get
        display = subparsers_org.add_parser('display', help="Display an organisation.")
        display.add_argument('id', help='ID of the organisation to display. Use "local" to display all local organisations, "external" for all remote organisations, and "all", for both.')
        # Search
        search = subparsers_org.add_parser('search', help="Search an organisation by name.")
        search.add_argument('name', help='(Partial) name of the organisation.')
        search.add_argument('-t', '--type', default='local', choices=['local', 'external', 'all'],
                            help='Use "local" to search in all local organisations, "external" for remote organisations, and "all", for both.')
        # Add
        add_org = subparsers_org.add_parser('add', help="Add an organisation.")
        add_org.add_argument('name', help='Organisation name.')
        add_org.add_argument('-u', '--uuid', default=None, help='UUID of the organisation.')
        add_org.add_argument('-d', '--description', default=[], nargs='+', help='Description of the organisation.')
        add_org.add_argument('-t', '--type', default=[], nargs='+', help='Type of the organisation.')
        add_org.add_argument('-n', '--nationality', default=None, help='Nationality of the organisation.')
        add_org.add_argument('-s', '--sector', default=[], nargs='+', help='Sector of the organisation.')
        add_org.add_argument('-c', '--contacts', default=[], nargs='+', help='Contact point(s) in the organisation.')
        add_org.add_argument('--not-local', default=True, action='store_false', help='**Not** a local organisation.')
        # Delete
        delete = subparsers_org.add_parser('delete', help="Delete an organisation.")
        delete.add_argument('id', help='ID of the organisation to delete.')
        # Edit
        edit = subparsers_org.add_parser('edit', help="Edit an organisation.")
        edit.add_argument('id', help='ID of the organisation to edit.')
        edit.add_argument('-n', '--name', help='Organisation name.')
        edit.add_argument('-u', '--uuid', help='UUID of the organisation.')
        edit.add_argument('-d', '--description', default=[], nargs='+', help='Description of the organisation.')
        edit.add_argument('-t', '--type', default=[], nargs='+', help='Type of the organisation.')
        edit.add_argument('--nationality', help='Nationality of the organisation.')
        edit.add_argument('-s', '--sector', default=[], nargs='+', help='Sector of the organisation.')
        edit.add_argument('-c', '--contacts', default=[], nargs='+', help='Contact point(s) in the organisation.')
        edit.add_argument('--not-local', default=True, action='store_false', help='**Not** a local organisation.')

        # User
        user = admin_parser.add_parser('user', help="User managment.")
        subparsers_user = user.add_subparsers(dest='user')
        # Get
        display = subparsers_user.add_parser('display', help="Display a user.")
        display.add_argument('id', help='ID of the user to display. Use "all" to display all users.')
        # Search
        search = subparsers_user.add_parser('search', help="Search a user by email.")
        search.add_argument('name', help='(Partial) email of the user.')
        # Add
        add_usr = subparsers_user.add_parser('add', help="Add a user.")
        add_usr.add_argument('email', help='User email address.')
        add_usr.add_argument('-o', '--org-id', default=None, help='Organisation ID of the user.')
        add_usr.add_argument('-r', '--role-id', default=None, help='Role of the user')
        add_usr.add_argument('-g', '--gpgkey', default=None, help='Path to the GPG public key export')
        add_usr.add_argument('-c', '--change-pw', default=None, action='store_true', help='Force thanging the password after next login')
        add_usr.add_argument('-t', '--termsaccepted', default=None, action='store_true', help='Set the TOC to accepted')
        add_usr.add_argument('-p', '--password', default=None, help='Set a new password')
        add_usr.add_argument('-d', '--disabled', default=None, action='store_true', help='Disable the account')
        # Delete
        delete = subparsers_user.add_parser('delete', help="Delete a user.")
        delete.add_argument('id', help='ID of the user to delete.')
        # Edit
        edit = subparsers_user.add_parser('edit', help="Edit a user.")
        edit.add_argument('id', help='ID of the user to edit.')
        edit.add_argument('-e', '--email', help='User email address.')
        edit.add_argument('-o', '--org-id', default=None, help='Organisation ID of the user.')
        edit.add_argument('-r', '--role-id', default=None, help='Role of the user')
        edit.add_argument('-g', '--gpgkey', default=None, help='Path to the GPG public key export')
        edit.add_argument('-c', '--change-pw', default=None, action='store_true', help='Force thanging the password after next login')
        edit.add_argument('-t', '--termsaccepted', default=None, action='store_true', help='Set the TOC to accepted')
        edit.add_argument('-p', '--password', default=None, help='Set a new password')
        edit.add_argument('-d', '--disabled', default=None, action='store_true', help='Disable the account')

        # Role
        role = admin_parser.add_parser('role', help="Role managment.")
        subparsers_role = role.add_subparsers(dest='role')
        # Get
        display = subparsers_role.add_parser('display', help="Display all the roles.")
        # Search
        search = subparsers_role.add_parser('search', help="Search a role by name.")
        search.add_argument('name', help='(Partial) name of the role.')

        # Tags
        t = admin_parser.add_parser('tag', help="Tag managment.")
        subparsers_tag = t.add_subparsers(dest='tag')
        # Get
        display = subparsers_tag.add_parser('display', help="Display all the tags.")
        # Search
        search = subparsers_tag.add_parser('search', help="Search a tag by name.")
        search.add_argument('name', help='(Partial) name of the tag.')

        self.categories = {0: 'Payload delivery', 1: 'Artifacts dropped', 2: 'Payload installation', 3: 'External analysis'}

    # ####### Generic Helpers ########
    def _get_eventid(self, quiet=False):
        if vars(self.args).get('event'):
            return self.args.event
        else:
            # Get current event ID if possible
            if not __sessions__.is_attached_misp(quiet):
                return None
            return __sessions__.current.misp_event.event.id

    def _has_error_message(self, result):
        if result.get('errors'):
            for message in result['errors']:
                self.log('error', message)
            return True
        elif result.get('error'):
            self.log('error', result.get('error'))
            return True
        return False

    def _search_local_hashes(self, event, open_session=True):
        local = []
        samples_count = 0
        if isinstance(event, MISPEvent):
            misp_event = event
        elif event.get('Event') is None:
            self.log('error', event)
            return
        else:
            misp_event = MISPEvent()
            misp_event.load(event)
        for a in misp_event.attributes:
            row = None
            if a.type == 'malware-sample':
                samples_count += 1
            if a.type in ('md5', 'sha1', 'sha256'):
                row = Database().find(key=a.type, value=a.value)
            elif a.type in ('filename|md5', 'filename|sha1', 'filename|sha256'):
                row = Database().find(key=a.type.split('|')[1], value=a.value.split('|')[1])
            elif a.type == 'malware-sample':
                row = Database().find(key='md5', value=a.value.split('|')[1])
            if row:
                local.append(row[0])
        self.log('info', 'Event {} contains {} samples.'.format(misp_event.id, samples_count))
        if not open_session:
            return
        shas = set([l.sha256 for l in local])
        if len(shas) == 1:
            __sessions__.new(get_sample_path(shas.pop()), MispEvent(misp_event, self.offline_mode))
        elif len(shas) > 1:
            self.log('success', 'The following samples are in this viper instance:')
            __sessions__.new(misp_event=MispEvent(misp_event, self.offline_mode))
            for s in shas:
                self.log('item', s)
        else:
            __sessions__.new(misp_event=MispEvent(misp_event, self.offline_mode))
            self.log('info', 'No known (in Viper) samples in that event.')

    def _find_related_id(self, event):
        if not event.RelatedEvent:
            return []
        related = [(_event.id, _event.info) for _event in event.RelatedEvent]
        to_return = list(set(related))
        to_return.sort(key=lambda tup: tup[0])
        return to_return

    def _dump(self, event=None):
        event_path = os.path.join(self.cur_path, 'misp_events')
        if not os.path.exists(event_path):
            os.makedirs(event_path)

        if not event:
            to_dump = __sessions__.current.misp_event.event
        elif isinstance(event, MISPEvent):
            to_dump = event
        else:
            to_dump = MISPEvent()
            to_dump.load(event)
        if to_dump.id:
            filename = str(to_dump.id)
        elif (__sessions__.is_attached_misp(True) and
                __sessions__.current.misp_event.current_dump_file):
            filename = __sessions__.current.misp_event.current_dump_file
        else:
            i = 1
            while True:
                filename = 'new_event_{}.json'.format(i)
                if not os.path.exists(os.path.join(event_path, filename)):
                    break
                i += 1

        path = os.path.join(event_path, filename)
        with open(path, 'w') as f:
            json.dump(to_dump, f, cls=EncodeFull)
        self.log('success', '{} stored successfully.'.format(filename.rstrip('.json')))
        return filename

    # ##########################################

    def yara(self):
        if self.offline_mode:
            self.log('error', 'Offline mode, unable to get yara rules')
            return
        ok = False
        data = None
        event_id = self._get_eventid()
        if event_id is None:
            return
        ok, data = self.misp.get_yara(event_id)
        if not ok:
            self.log('error', data)
            return
        rule_path = os.path.join(VIPER_ROOT, 'data/yara', self.args.event + '.yara')
        if os.path.exists(rule_path):
            self.log('error', 'File {} already exists.'.format(rule_path))
            return
        with open(rule_path, 'wb') as f:
            f.write(data.encode('utf-8'))
        self.log('success', 'The yara rules of event {} have been downloaded: {}'.format(self.args.event, rule_path))

    def upload(self):
        if self.offline_mode:
            self.log('error', 'Offline mode, unable to upload a sample')
            return
        categ = self.categories.get(self.args.categ)
        if self.args.info is not None:
            info = ' '.join(self.args.info)
        else:
            info = None
        if self.args.comment is not None:
            comment = ' '.join(self.args.comment)
        else:
            comment = None
        # No need to check the output: is the event_id is none, we create a new one.
        event_id = self._get_eventid(True)
        try:
            result = self.misp.upload_sample(__sessions__.current.file.name, __sessions__.current.file.path,
                                             event_id, self.args.distrib, self.args.ids, categ, info, comment,
                                             self.args.analysis, self.args.threat)
        except Exception as e:
            self.log('error', e)
            return
        if not self._has_error_message(result):
            self.log('success', "File uploaded successfully")
            if event_id is None:
                event_id = result['id']
            full_event = self.misp.get(event_id)
            if not self._has_error_message(full_event):
                return __sessions__.new(misp_event=MispEvent(full_event, self.offline_mode))

    def searchall(self):
        if self.args.query:
            self._search(' '.join(self.args.query))
        else:
            if not __sessions__.is_attached_file(True):
                self.log('error', "Not attached to a file, nothing to search for.")
                return False
            to_search = [__sessions__.current.file.md5, __sessions__.current.file.sha1, __sessions__.current.file.sha256]
            for q in to_search:
                self._search(q)

    def _search(self, query):
        if self.offline_mode:
            self.log('error', 'Offline mode, unable to search')
            return
        result = self.misp.search_all(query)

        if self._has_error_message(result):
            return
        self.log('success', '{} matches on the following events:'.format(query))
        for e in result['response']:
            nb_samples = 0
            nb_hashes = 0
            me = MISPEvent()
            me.load(e)
            for a in me.attributes:
                if a.type == 'malware-sample':
                    nb_samples += 1
                if a.type in ('md5', 'sha1', 'sha256', 'filename|md5', 'filename|sha1', 'filename|sha256'):
                    nb_hashes += 1
            self.log('item', '{} ({} samples, {} hashes) - {}{}{}'.format(me.info, nb_samples, nb_hashes, self.url, '/events/view/', me.id))

    def pull(self):
        if self.offline_mode:
            self.log('error', 'Offline mode, unable to pull a remote event')
            return
        open_session = len(self.args.event) == 1
        for e in self.args.event:
            event = self.misp.get(e)
            if not self._has_error_message(event):
                self._search_local_hashes(event, open_session)
                self._dump(event)

    def publish(self):
        __sessions__.current.misp_event.event.publish()
        if self.offline_mode:
            self._dump()
        else:
            event = self.misp.update(__sessions__.current.misp_event.event._json())
            if not self._has_error_message(event):
                self.log('success', 'Event {} published.'.format(event['Event']['id']))
                __sessions__.new(misp_event=MispEvent(event, self.offline_mode))

    def show(self):
        current_event = __sessions__.current.misp_event.event

        related = self._find_related_id(current_event)
        if len(related) > 0:
            self.log('info', 'Related events:')
            for r, title in related:
                self.log('item', '{}/events/view/{} - {}'.format(self.url.rstrip('/'), r, title))

        header = ['type', 'value', 'comment', 'related']
        rows = []
        for a in current_event.attributes:
            # FIXME: this has been removed upstream: https://github.com/MISP/MISP/issues/1793
            # Keeping it like that for now, until we decide how to re-enable it
            idlist = []
            if a.RelatedAttribute:
                for r in a.RelatedAttribute:
                    # idlist.append(r.id)
                    pass
            rows.append([a.type, a.value, '\n'.join(textwrap.wrap(a.comment, 30)), '\n'.join(textwrap.wrap(' '.join(idlist), 15))])
        self.log('table', dict(header=header, rows=rows))
        if current_event.published:
            self.log('info', 'This event has been published')
        else:
            self.log('info', 'This event has not been published')
        if __sessions__.current.misp_event.event.id:
            self.log('info', 'Link to Event: {}/events/view/{}'.format(self.url.rstrip('/'), __sessions__.current.misp_event.event.id))

    def run(self):
        super(MISP, self).run()

        if self.args is None:
            return

        if not HAVE_PYMISP:
            self.log('error', "Missing dependency, install pymisp (`pip install pymisp`)")
            return

        self.offline_mode = False
        if self.args.on:
            self.offline_mode = False
            if __sessions__.is_attached_misp(True):
                __sessions__.current.misp_event.off = False
        elif self.args.off or (__sessions__.is_attached_misp(True) and
                               __sessions__.current.misp_event.off):
            self.offline_mode = True
            if __sessions__.is_attached_misp(True):
                __sessions__.current.misp_event.off = True

        self.url = self.args.url
        if self.url is None:
            self.url = cfg.misp.misp_url
        if self.url is None:
            self.log('error', "This command requires the URL of the MISP instance you want to query.")
            return

        self.key = self.args.key
        if self.key is None:
            self.key = cfg.misp.misp_key
        if self.key is None:
            self.log('error', "This command requires a MISP private API key.")
            return

        if not self.args.verify:
            verify = False
        else:
            verify = cfg.misp.misp_verify

        # Capture default distribution and sharing group settings. Backwards compatability and empty string check
        self.distribution = cfg.misp.get("misp_distribution", None)
        self.distribution = None if self.distribution == "" else self.distribution
        if type(self.distribution) not in (type(None), int):
            self.distribution = None
            self.log('info', "The distribution stored in viper config is not an integer, setting to None")

        self.sharinggroup = cfg.misp.get("misp_sharinggroup", None)
        self.sharinggroup = None if self.sharinggroup == "" else self.sharinggroup
        if type(self.sharinggroup) not in (type(None), int):
            self.sharinggroup = None
            self.log('info', "The sharing group stored in viper config is not an integer, setting to None")

        if cfg.misp.misp_taxonomies_directory:
            self.local_dir_taxonomies = cfg.misp.misp_taxonomies_directory

        if not self.offline_mode:
            try:
                self.misp = PyMISP(self.url, self.key, verify, 'json')
            except PyMISPError as e:
                self.log('error', e.message)
                return

        # Require an open MISP session
        if self.args.subname in ['add_hashes', 'add', 'show', 'publish'] and not __sessions__.is_attached_misp():
            return

        # Require an open file session
        if self.args.subname in ['upload'] and not __sessions__.is_attached_file():
            return

        try:
            if self.args.subname == 'upload':
                self.upload()
            elif self.args.subname == 'search':
                self.searchall()
            elif self.args.subname == 'download':
                self.download()
            elif self.args.subname == 'check_hashes':
                self.check_hashes()
            elif self.args.subname == 'yara':
                self.yara()
            elif self.args.subname == 'pull':
                self.pull()
            elif self.args.subname == 'create_event':
                self.create_event()
            elif self.args.subname == 'add':
                self.add()
            elif self.args.subname == 'add_hashes':
                self.add_hashes()
            elif self.args.subname == 'show':
                self.show()
            elif self.args.subname == 'open':
                self.open_samples()
            elif self.args.subname == 'publish':
                self.publish()
            elif self.args.subname == 'version':
                self.version()
            elif self.args.subname == 'store':
                self.store()
            elif self.args.subname == 'tag':
                self.tag()
            elif self.args.subname == 'admin':
                self.admin()
            else:
                self.log('error', "No calls defined for this command.")
        except requests.exceptions.HTTPError as e:
            self.log('error', e)
