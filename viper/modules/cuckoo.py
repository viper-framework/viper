# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

import os
import shutil
import logging
import tempfile
import tarfile
import contextlib
from io import BytesIO

from viper.common.abstracts import Module
from viper.core.session import __sessions__
from viper.core.database import Database
from viper.common.objects import File
from viper.core.storage import store_sample
from viper.core.config import __config__

log = logging.getLogger('viper')

cfg = __config__
cfg.parse_http_client(cfg.cuckoo)


# context manager for dropped files
@contextlib.contextmanager
def create_temp():
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)


class Cuckoo(Module):
    cmd = 'cuckoo'
    description = 'Submit the file to Cuckoo Sandbox'
    authors = ['nex', 'Kevin Breen']

    def __init__(self):
        super(Cuckoo, self).__init__()
        self.parser.add_argument('-s', '--status', action='store_true', help='Get Analysis Status')
        self.parser.add_argument('-f', '--file', action='store_true', help='Submit File for analysis')
        self.parser.add_argument('-r', '--resubmit', action='store_true', help='Resubmit Analysis of File')
        self.parser.add_argument('-d', '--dropped', type=int, help='Get all Dropped Samples from task id')
        self.parser.add_argument('-m', '--machine', help='Name of Machine or all')
        self.parser.add_argument('-p', '--package', help='Select a package type to run')
        self.parser.add_argument('-o', '--options', help='Options in the format "procmemdump=yes,nohuman=yes"')

    def add_file(self, file_path, tags, parent):
        obj = File(file_path)
        new_path = store_sample(obj)
        if new_path:
            # Add file to the database.
            db = Database()
            db.add(obj=obj, tags=tags, parent_sha=parent)
            return obj.sha256

    def api_query(self, api_method, api_uri, files=None, params=None):
        if files:
            try:
                response = requests.post(api_uri, files=files, data=params,
                                         proxies=cfg.cuckoo.proxies, verify=cfg.cuckoo.verify, cert=cfg.cuckoo.cert)

            except requests.ConnectionError:
                self.log('error', "Unable to connect to Cuckoo API at '{0}'.".format(api_uri))
                return
            except Exception as e:
                self.log('error', "Failed performing request at '{0}': {1}".format(api_uri, e))
                return

        if not files and api_method == 'post':
            # POST to API
            return

        if not files and api_method == 'get':
            # GET from API
            try:
                response = requests.get(api_uri, proxies=cfg.cuckoo.proxies, verify=cfg.cuckoo.verify, cert=cfg.cuckoo.cert)
            except requests.ConnectionError:
                self.log('error', "Unable to connect to Cuckoo API at '{0}'.".format(api_uri))
                return
            except Exception as e:
                self.log('error', "Failed performing request at '{0}': {1}".format(api_uri, e))
                return
        return response

    def run(self):
        super(Cuckoo, self).run()
        if self.args is None:
            return

        # Get the connections string from config

        if cfg.cuckoo.cuckoo_host:
            cuckoo_host = cfg.cuckoo.cuckoo_host
        else:
            self.log('error', 'Cuckoo Config Not Set')
            return

        if cfg.cuckoo.cuckoo_modified:
            search_url = '{0}/api/tasks/search/sha256'.format(cuckoo_host)
            submit_file_url = '{0}/api/tasks/create/file/'.format(cuckoo_host)
            status_url = '{0}/api/cuckoo/status'.format(cuckoo_host)
        else:
            search_url = '{0}/tasks/list'.format(cuckoo_host)
            submit_file_url = '{0}/tasks/create/file'.format(cuckoo_host)
            status_url = '{0}/cuckoo/status'.format(cuckoo_host)

        if self.args.status:
            # get the JSON
            try:
                api_status = self.api_query('get', status_url).json()
            except Exception:
                return

            if cfg.cuckoo.cuckoo_modified:
                cuckoo_version = api_status['data']['version']
                machines = '{0}/{1}'.format(api_status['data']['machines']['available'],
                                            api_status['data']['machines']['total']
                                            )
                tasks = [api_status['data']['tasks']['completed'],
                         api_status['data']['tasks']['pending'],
                         api_status['data']['tasks']['reported'],
                         api_status['data']['tasks']['running'],
                         api_status['data']['tasks']['total']
                         ]
            else:
                cuckoo_version = api_status['version']
                machines = '{0}/{1}'.format(api_status['machines']['available'],
                                            api_status['machines']['total']
                                            )
                tasks = [api_status['tasks']['completed'],
                         api_status['tasks']['pending'],
                         api_status['tasks']['reported'],
                         api_status['tasks']['running'],
                         api_status['tasks']['total']
                         ]

            self.log('info', "Cuckoo")
            self.log('item', "Version: {0}".format(cuckoo_version))
            self.log('item', "Available Machines: {0}".format(machines))

            self.log('info', "Tasks")
            self.log('item', "Completed: {0}".format(tasks[0]))
            self.log('item', "Pending: {0}".format(tasks[1]))
            self.log('item', "Reported: {0}".format(tasks[2]))
            self.log('item', "Running: {0}".format(tasks[3]))
            self.log('item', "Total: {0}".format(tasks[4]))

        if self.args.file:
            if not __sessions__.is_set():
                self.log('error', "No open session")
                return

            if not self.args.resubmit:
                # Check for existing Session
                if cfg.cuckoo.cuckoo_modified:
                    search_results = self.api_query('get', '{0}/{1}'.format(search_url, __sessions__.current.file.sha256)).json()
                    if search_results['data'] != "Sample not found in database":
                        self.log('info', "Found {0} Results".format(len(search_results['data'])))
                        rows = []
                        header = ['ID', 'Started On', 'Status', 'Completed On']
                        for result in search_results['data']:
                            rows.append([result['id'], result['started_on'], result['status'], result['completed_on']])
                        self.log('table', dict(header=header, rows=rows))
                        self.log('warning', "use -r, --resubmit to force a new analysis")
                        return
                else:
                    search_results = self.api_query('get', search_url).json()
                    count = 0
                    if 'tasks' in search_results:
                        rows = []
                        header = ['ID', 'Started On', 'Status', 'Completed On']
                        for result in search_results['tasks']:
                            try:
                                if result['sample']['sha256'] == __sessions__.current.file.sha256:
                                    rows.append([result['id'], result['started_on'], result['status'], result['completed_on']])
                                    count += 1
                            except Exception:
                                pass
                        if len(rows) > 0:
                            self.log('info', "Found {0} Results".format(count))
                            self.log('table', dict(header=header, rows=rows))
                            self.log('warning', "use -r, --resubmit to force a new analysis")
                            return
            # Submit the file
            params = {}
            if self.args.machine:
                params['machine'] = self.args.machine
            if self.args.package:
                params['package'] = self.args.package
            if self.args.options:
                params['options'] = self.args.options

            files = {'file': (__sessions__.current.file.name, BytesIO(__sessions__.current.file.data))}
            submit_file = self.api_query('post', submit_file_url, files=files, params=params).json()
            try:
                self.log('info', "Task Submitted ID: {0}".format(submit_file['task_id']))
            except KeyError:
                try:
                    self.log('info', "Task Submitted ID: {0}".format(submit_file['task_ids'][0]))
                except KeyError:
                    self.log('error', submit_file)

        if self.args.dropped and __sessions__.is_set():
            try:
                task_id = int(self.args.dropped)
            except Exception:
                self.log('error', "Not a valid task id")

            # Handle Modified-Cuckoo
            if cfg.cuckoo.cuckoo_modified:
                dropped_url = '{0}/api/tasks/get/dropped/{1}'.format(cuckoo_host, task_id)
            else:
                dropped_url = '{0}/tasks/report/{1}/dropped'.format(cuckoo_host, task_id)

            dropped_result = self.api_query('get', dropped_url)

            if dropped_result.content.startswith('BZ'):
                # explode BZ
                with tarfile.open(fileobj=BytesIO(dropped_result.content)) as bz_file:
                    for item in bz_file:
                        # Write Files to tmp dir
                        if item.isreg():
                            # Create temp dirs to prevent duplicate filenames creating Errors
                            with create_temp() as temp_dir:
                                file_path = os.path.join(temp_dir, os.path.basename(item.name))
                                with open(file_path, 'wb') as out:
                                    out.write(bz_file.extractfile(item).read())
                                # Add the file
                                self.log('info', "Storing Dropped File {0}".format(item.name))
                                self.add_file(file_path,
                                              'Cuckoo_ID_{0}'.format(task_id),
                                              __sessions__.current.file.sha256
                                              )
                return

            else:
                if not __sessions__.is_set():
                    self.log('error', "No open session")
                    return
                try:
                    json_error = dropped_result.json()
                    self.log('error', json_error['data'])
                except Exception as e:
                    self.log('error', "Your broke something, {0}".format(e))
