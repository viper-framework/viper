# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import zipfile
import tempfile
import io
import os
import json

import jbxapi

from viper.common.abstracts import Module
from viper.common.objects import File
from viper.core.storage import store_sample
from viper.core.database import Database
from viper.core.config import __config__
from viper.core.session import __sessions__

cfg = __config__
cfg.parse_http_client(cfg.joesandbox)


class JoeSandbox(Module):
    cmd = 'joe'
    description = 'Manage sandbox analyses with Joe Sandbox'
    authors = ['Joe Security LLC']

    # store for the running analyses (class variable)
    _tasks = []

    def __init__(self):
        super(JoeSandbox, self).__init__()

        group = self.parser.add_mutually_exclusive_group()
        group.add_argument('-s', '--submit', action='store_true', help='Submit file for analysis.')
        group.add_argument('-t', '--tasks', action='store_true', help='Show information about all submitted tasks.')
        group.add_argument('-d', '--dropped', action='store_true', help='Get all dropped binaries from all tasks.')
        group.add_argument('-r', '--report', action='store_true', help='Show a small report.')
        group.add_argument('-c', '--clear', action='store_true', help="Empty the list of tasks.")

    def run(self):
        super(JoeSandbox, self).run()
        if not cfg.joesandbox:
            self.log("error", 'The JoeSandbox module cannot be used unless the configuration is defined.')
            return

        self.joe = jbxapi.JoeSandbox(apiurl=cfg.joesandbox.apiurl,
                                     apikey=cfg.joesandbox.apikey,
                                     accept_tac=cfg.joesandbox.accept_tac,
                                     verify_ssl=cfg.joesandbox.verify,
                                     user_agent="viper")

        if self.args is None:
            return

        if not __sessions__.is_set():
            self.log('error', "No open session.")
            return

        try:
            if self.args.submit:
                self.submit()
            elif self.args.tasks:
                self.tasks()
            elif self.args.dropped:
                self.dropped()
            elif self.args.clear:
                self.clear()
            elif self.args.report:
                self.report()
        except jbxapi.JoeException as e:
            self.log("error", e)

    def submit(self):
        with open(__sessions__.current.file.path, "rb") as f:
            # prepare parameters
            params = _submission_parameters()
            params.setdefault("tags", []).extend(__sessions__.current.file.tags.split())

            filename = __sessions__.current.file.name

            data = self.joe.submit_sample((filename, f), params=params)

        submission_id = data["submission_id"]

        t = _Task(__sessions__.current.file.sha256, submission_id)
        self._tasks.append(t)
        self.log('success', "Submission {0}".format(submission_id))

    def tasks(self):
        if not self._tasks:
            self.log('warning', "No pending tasks.")
            return

        self._update_tasks()

        self.log("info", "Tasks:")
        for task in self._tasks:
            line = "{0}: {1}".format(task.submission_id, task.status)

            # mark tasks belonging to current session
            if task.sha256 == __sessions__.current.file.sha256:
                line += " *"

            self.log("item", line)

    def _update_tasks(self):
        for task in self._tasks:
            if task.status != "finished":
                task.info = self.joe.submission_info(task.submission_id)

    def dropped(self):
        self._update_tasks()

        tasks = [task for task in self._tasks if not task.dropped_extracted and task.status == "finished"]

        if not tasks:
            self.log('warning', "No tasks found or not finished yet.")
            return

        for task in tasks:
            task.dropped_extracted = True

            for webid in task.webids:
                f = io.BytesIO()
                try:
                    self.joe.analysis_download(webid, "bins", file=f)
                except jbxapi.JoeException:
                    self.log('info', "Analysis {0} did not drop anything.".format(webid))
                    continue

                f.seek(0)

                with zipfile.ZipFile(f) as z:
                    z.setpassword("infected")

                    for name in z.namelist():
                        self.log('info', name)
                        try:
                            name_str = unicode(name, 'utf-8', 'replace')
                        except NameError:
                            name_str = str(name, 'utf-8', 'replace')

                        try:
                            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                                data = z.read(name)
                                tmp.write(data)
                            _add_file(tmp.name, name=name_str, tags="joe_webid_{0}".format(webid), parent_sha=task.sha256)
                            self.log("success", "Inserted {0}".format(name_str))
                        finally:
                            os.remove(tmp.name)

    def clear(self):
        self._tasks[:] = []
        self.log('info', "Removed all tasks from the list.")

    def report(self):
        tasks = [task for task in self._tasks if task.sha256 == __sessions__.current.file.sha256 and task.status == "finished"]

        if not tasks:
            self.log('warning', "No matching task found or not finished yet.")
            return

        # filter to only have those which started analyses
        tasks = [task for task in tasks if task.most_relevant_webid is not None]

        if not tasks:
            self.log('warning', "No report available since the submission did not spawn any analyses.")
            return

        task = tasks[0]

        _, content = self.joe.analysis_download(task.most_relevant_webid, "irjsonfixed")
        content = json.loads(content.decode())
        self.log('info', json.dumps(content, indent=4))


class _Task(object):
    """
    Data store for joe sandbox tasks.
    """
    info = None
    dropped_extracted = False

    def __init__(self, sha256, submission_id):
        self.sha256 = sha256
        self.submission_id = submission_id

    @property
    def status(self):
        try:
            return self.info["status"]
        except Exception:
            return "submitted"

    @property
    def webids(self):
        try:
            return [a["webid"] for a in self.info["analyses"]]
        except Exception:
            return []

    @property
    def most_relevant_webid(self):
        try:
            return self.info["most_relevant_analysis"]["webid"]
        except Exception:
            return None


def _add_file(file_path, name, tags, parent_sha):
    obj = File(file_path)
    new_path = store_sample(obj)
    if new_path:
        db = Database()
        db.add(obj=obj, name=name, tags=tags, parent_sha=parent_sha)
        return obj.sha256
    else:
        return None


def _submission_parameters():
    params = {}
    for param in jbxapi.submission_defaults:
        value = getattr(cfg.joesandbox, param)
        if value is not None:
            if param in ("tags", "systems"):
                value = value.split()
            params[param] = value
    return params
