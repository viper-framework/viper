# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

# Standard Imports
import os
import re
import json
import tempfile
import contextlib
import shutil
import requests
from operator import itemgetter

# Logging
import logging

# Django Imports
from django.shortcuts import render, redirect
from django.urls import reverse
from django.http import HttpResponse, Http404
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.views.generic import TemplateView
from django.contrib import messages
from django.core.files.temp import NamedTemporaryFile

# Viper imports
from viper.core.session import __sessions__
from viper.core.plugins import __modules__
from viper.core.project import __project__
from viper.core.project import get_project_list
from viper.common.objects import File
from viper.common import network
from viper.core.storage import store_sample, get_sample_path
from viper.core.database import Database
from viper.core.archiver import Extractor
from viper.core.ui.commands import Commands
from viper.common.constants import VIPER_ROOT
from viper.common.autorun import autorun_module
from viper.core.config import __config__

try:
    from scandir import walk  # noqa
except ImportError:
    from os import walk  # noqa
try:
    from subprocess import getoutput
except ImportError:
    from commands import getoutput  # commands was deprecated in Py2.

log = logging.getLogger("viper-web")
cfg = __config__


##
# Helper Functions
##

# Module Dicts - TODO(frennkie) can this be auto generated (introspection)?!
mod_dict = {'apk': {'help': '-h', 'info': '-i', 'perm': '-p', 'list': '-f', 'all': '-a', 'dump': '-d'},
            'clamav': {'run': ''},
            'debup': {'info': '', 'extract': '-s'},
            'editdistance': {'run': ''},
            'elf': {'sections': '--sections', 'segments': '--segments', 'symbols': '--symbols',
                    'interp': '--interpreter', 'dynamic': '--dynamic'},
            'email': {'envelope': '-e', 'attach': '-f', 'header': '-r', 'trace': '-t', 'traceall': '-T', 'spoof': '-s',
                      'all': '-a'},
            'exif': {'run': ''},
            'fuzzy': {'run': ''},
            'html': {'scripts': '-s', 'links': '-l', 'iframe': '-f', 'embed': '-e', 'images': '-i', 'dump': '-d'},
            'idx': {'run': ''},
            'image': {'ghiro': '--ghiro'},
            'jar': {'run': ''},
            'office': {'meta': '-m', 'oleid': '-o', 'streams': '-s', 'export': '-e'},
            'pdf': {'id': 'id', 'streams': 'streams'},
            'pe': {'imports': 'imports', 'exports': 'exports', 'res': 'resources', 'imp': 'imphash',
                   'compile': 'compiletime',
                   'peid': 'peid', 'security': 'security', 'language': 'language', 'sections': 'sections',
                   'pehash': 'pehash'},
            'rat': {'auto': '-a', 'list': '-l'},
            'reports': {'malwr': '--malwr', 'anubis': '--anubis', 'threat': '--threat', 'joe': '--joe',
                        'meta': '--meta'},
            'shellcode': {'run': ''},
            'strings': {'all': '-a', 'hosts': '-H'},
            'swf': {'decom': 'decompress'},
            'virustotal': {'scan': '', 'submit': '-s'},
            'xor': {'xor': '', 'rot': '-r', 'all': '-a', 'export': '-o'},
            'yara': {'scan': 'scan -t', 'all': 'scan -a -t'}
            }


# context manager for file uploader
@contextlib.contextmanager
def upload_temp():
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)


def open_db(project):
    # Check for valid project
    if project == 'default':
        __project__.open(project)
        return Database()
    else:
        try:
            __project__.open(project)
            return Database()
        except Exception:
            return False


def print_output(output):
    if not output:
        return '<p class="text-danger">! The command Generated no Output</p>'
    return_html = ''
    for entry in output:
        # Skip lines that say seesion opened
        if 'Session opened on' in entry['data']:
            continue
        if entry['type'] == 'info':
            return_html += '<p class="text-primary">{0}</p>'.format(entry['data'])
            # self.log('info', entry['data'])
        elif entry['type'] == 'item':
            return_html += '<li class="text-primary">{0}</li>'.format(entry['data'])
        elif entry['type'] == 'warning':
            return_html += '<p class="text-warning">{0}</p>'.format(entry['data'])
        elif entry['type'] == 'error':
            return_html += '<p class="text-danger">{0}</p>'.format(entry['data'])
        elif entry['type'] == 'success':
            return_html += '<p class="text-success">{0}</p>'.format(entry['data'])
        elif entry['type'] == 'table':
            # set the table
            return_html += '<table class="table table-bordered">'
            # Column Titles
            return_html += '<tr>'
            for column in entry['data']['header']:
                return_html += '<th>{0}</th>'.format(column)
            return_html += '</tr>'
            # Rows
            for row in entry['data']['rows']:
                return_html += '<tr>'
                for cell in row:
                    return_html += '<td>{0}</td>'.format(cell)
                return_html += '</tr>'
            # Close table
            return_html += '</table>'
        else:
            return_html += '<p>{0}</p>'.format(entry['data'])
    return return_html


def parse(data):
    args = []
    # Split words by white space.
    words = data.split()
    # First word is the root command.
    root = words[0]
    # If there are more words, populate the arguments list.
    if len(words) > 1:
        args = words[1:]
    return root, args


def parse_text(module_text):
    # String to hold the new text
    set_text = ''
    # Split in to lines.
    for line in module_text.split('\n'):
        # Remove the colour codes
        line = re.sub('\[(\d)+m', '', line.replace('\x1b', ''))
        # Ignore the line that says we opened a session
        if 'Session opened on' in line:
            continue
        # add text the string
        set_text += '{0}\n'.format(line)
    return set_text


# this will allow complex command line parameters to be passed in via the web gui
def module_cmdline(cmd_line, file_hash):
    html = ""
    cmd = Commands()
    split_commands = cmd_line.split(';')
    for split_command in split_commands:
        split_command = split_command.strip()
        if not split_command:
            continue
        root, args = parse(split_command)
        try:
            if root in cmd.commands:
                cmd.commands[root]['obj'](*args)
                html += print_output(cmd.output)
                del (cmd.output[:])
            elif root in __modules__:
                # if prev commands did not open a session open one on the current file
                if file_hash:
                    path = get_sample_path(file_hash)
                    __sessions__.new(path)
                module = __modules__[root]['obj']()
                module.set_commandline(args)
                module.run()

                html += print_output(module.output)
                if cfg.modules.store_output and __sessions__.is_set():
                    Database().add_analysis(file_hash, split_command, module.output)
                del (module.output[:])
            else:
                html += '<p class="text-danger">{0} is not a valid command</p>'.format(cmd_line)
        except Exception:
            html += '<p class="text-danger">We were unable to complete the command {0}</p>'.format(cmd_line)
    __sessions__.close()
    return html


def add_file(file_path, name=None, tags=None, parent=None):
    obj = File(file_path)
    new_path = store_sample(obj)
    print(new_path)

    if not name:
        name = os.path.basename(file_path)

    # success = True
    if new_path:
        # Add file to the database.
        db = Database()
        db.add(obj=obj, name=name, tags=tags, parent_sha=parent)

        # AutoRun Modules
        if cfg.autorun.enabled:
            autorun_module(obj.sha256)
            # Close the open session to keep the session table clean
            __sessions__.close()
        return obj.sha256

    else:
        # ToDo Remove the stored file if we cant write to DB
        return


##
# Class Based Views
##

# Main Page
class MainPageView(LoginRequiredMixin, TemplateView):
    """Main Page"""
    def get(self, request, *args, **kwargs):
        template_name = "viperweb/index.html"

        # default to "default" project if none given
        project = kwargs.get('project', 'default')
        db = open_db(project)

        # Get all Samples
        sample_list = db.find('all')

        # set pagination details
        page = request.GET.get('page', 1)
        page_count = request.GET.get('count', 15)

        sample_count = len(sample_list)
        first_sample = int(page) * int(page_count) - int(page_count) + 1
        last_sample = int(page) * int(page_count)

        if last_sample > sample_count:
            last_sample = sample_count

        paginator = Paginator(sample_list, page_count)
        try:
            samples = paginator.page(page)
        except PageNotAnInteger:
            samples = paginator.page(1)
        except EmptyPage:
            samples = paginator.page(paginator.num_pages)

        return render(request, template_name, {'sample_list': samples,
                                               'sample_count': sample_count,
                                               'samples': [first_sample, last_sample],
                                               'extractors': Extractor().extractors,
                                               'project': project,
                                               'projects': get_project_list()})


class UrlDownloadView(LoginRequiredMixin, TemplateView):
    """Download a file from URL and add to project"""
    def post(self, request, *args, **kwargs):
        # Set Project
        project = request.POST.get('project', 'default')
        open_db(project)

        url = request.POST.get('url')
        tags = request.POST.get('tag_list')
        tags = "url," + tags

        if request.POST.get('tor'):
            downloaded_file = network.download(url, tor=True)
        else:
            downloaded_file = network.download(url, tor=False)

        if downloaded_file is None:
            messages.error(request, "server can't download from URL")
            return redirect(reverse("main-page-project", kwargs={"project": project}))

        tf = NamedTemporaryFile()
        tf.write(downloaded_file)

        if not tf:
            messages.error(request, "server can't download from URL")
            return redirect(reverse("main-page-project", kwargs={"project": project}))
        tf.flush()

        sha_256 = add_file(tf.name, name=url.split('/')[-1], tags=tags)
        if sha_256:
            messages.success(request, "stored file in database: {}".format(tf.name))
            return redirect(reverse('main-page-project', kwargs={'project': project}))
        else:
            messages.error(request, "Unable to Store The File, already in database")
            return redirect(reverse("main-page-project", kwargs={"project": project}))


class VtDownloadView(LoginRequiredMixin, TemplateView):
    """Download a file from Virustotal and add to project"""

    # VirusTotal Download
    # TODO(frennkie) this most likely doesn't work
    #   virustotal -d does not take a parameter - so providing a vt_hash will fail
    #   virustotal --search <vt_hash> -d would make sense but requires a API key for the
    #   private VT API (which I don't have)

    def post(self, request, *args, **kwargs):
        # Set Project
        project = request.POST.get('project', 'default')
        open_db(project)

        vt_hash = request.POST.get('vt_hash')
        tags = request.POST.get('tag_list')
        cmd_line = 'virustotal -d {0}; store; tags -a {1}'.format(vt_hash, tags)

        module_results = module_cmdline(cmd_line, False)

        if 'Stored' in module_results:
            return redirect(reverse("main-page-project", kwargs={"project": project}))
        else:
            messages.error(request, "Unable to download file {0}".format(module_results))
            return redirect(reverse("main-page-project", kwargs={"project": project}))


# File View
class FileView(LoginRequiredMixin, TemplateView):
    """Show details for a file/sample"""
    def get(self, request, *args, **kwargs):
        template_name = "viperweb/file.html"

        # default to "default" project if none given
        project = kwargs.get('project', 'default')
        db = open_db(project)

        sha256 = kwargs.get('sha256')
        if not sha256:
            log.error("no sha256 hashed provided")
            raise Http404("no sha256 hashed provided")

        path = get_sample_path(sha256)
        if not path:
            raise Http404("could not retrieve file for sha256 hash: {}".format(sha256))
        __sessions__.new(path)

        # Get the file info  - TODO (frennkie) this should not be done here.. move it to backend
        file_info = {
            'id': __sessions__.current.file.id,
            'name': __sessions__.current.file.name,
            'path': __sessions__.current.file.path,
            'size': __sessions__.current.file.size,
            'type': __sessions__.current.file.type,
            'mime': __sessions__.current.file.mime,
            'md5': __sessions__.current.file.md5,
            'sha1': __sessions__.current.file.sha1,
            'sha256': __sessions__.current.file.sha256,
            'sha512': __sessions__.current.file.sha512,
            'ssdeep': __sessions__.current.file.ssdeep,
            'crc32': __sessions__.current.file.crc32,
            'parent': __sessions__.current.file.parent,
            'children': __sessions__.current.file.children.split(','),
            'tag_list': __sessions__.current.file.tags
        }

        # Get additional details for file
        malware = db.find(key='sha256', value=sha256)  # TODO (frennkie) this should not be done here.. move it to backend
        if not malware:
            raise Http404("could not find file for sha256 hash: {}".format(sha256))

        note_list = []
        notes = malware[0].note
        if notes:
            for note in notes:
                note_list.append({'title': note.title,
                                  'body': note.body,
                                  'id': note.id})

        module_history = []
        analysis_list = malware[0].analysis
        if analysis_list:
            for item in analysis_list:
                module_history.append({'id': item.id,
                                       'cmd_line': item.cmd_line})

        tag_list = db.list_tags_for_malware(sha256)

        return render(request, template_name, {'file_info': file_info,
                                               'note_list': note_list,
                                               'tag_list': tag_list,
                                               'project': project,
                                               'projects': get_project_list(),
                                               'module_history': module_history})


class RunModuleView(LoginRequiredMixin, TemplateView):
    """Run a module and return output"""
    def post(self, request, *args, **kwargs):
        # Get the hash of the file we want to run a command against
        file_hash = request.POST.get('file_hash')
        print("Here: {}".format(file_hash))
        if len(file_hash) != 64:
            file_hash = False
        # Lot of logic here to decide what command you entered.
        module_name = request.POST.get('module')
        module_args = request.POST.get('args')
        cmd_line = request.POST.get('cmdline')
        module_history = request.POST.get('moduleHistory', ' ')
        cmd_string = ''
        # Order of precedence
        # moduleHistory, cmd_line, module_name

        if module_history != ' ':
            result = Database().get_analysis(module_history)
            module_results = print_output(json.loads(result.results))
            html = '<p class="text-success">Result for "{0}" stored on {1}</p>'.format(result.cmd_line, result.stored_at)
            html += str(parse_text(module_results))
            return HttpResponse('<pre>{0}</pre>'.format(html))
        if cmd_line:
            cmd_string = cmd_line
        elif module_args:
            cmd_string = '{0} {1}'.format(module_name, mod_dict[module_name][module_args])
        module_results = module_cmdline(cmd_string, file_hash)
        return HttpResponse('<pre>{0}</pre>'.format(str(parse_text(module_results))))


class HexView(LoginRequiredMixin, TemplateView):
    """Read file a return as Hex"""
    def post(self, request, *args, **kwargs):
        # get post data
        file_hash = request.POST.get('file_hash')
        try:
            hex_offset = int(request.POST.get('hex_start'))
        except:
            return '<p class="text-danger">Error Generating Request</p>'
        hex_length = 256

        # get file path
        hex_path = get_sample_path(file_hash)

        # create the command string
        hex_cmd = 'hd -s {0} -n {1} {2}'.format(hex_offset, hex_length, hex_path)

        # get the output
        hex_string = getoutput(hex_cmd)
        # Format the data
        html_string = ''
        hex_rows = hex_string.split('\n')
        for row in hex_rows:
            if len(row) > 9:
                off_str = row[0:8]
                hex_str = row[9:58]
                asc_str = row[58:78]
                asc_str = asc_str.replace('"', '&quot;')
                asc_str = asc_str.replace('<', '&lt;')
                asc_str = asc_str.replace('>', '&gt;')
                html_string += '<div class="row"><span class="text-primary mono">{0}</span> \
                                <span class="text-muted mono">{1}</span> <span class="text-success mono"> \
                                {2}</span></div>'.format(off_str, hex_str, asc_str)
        # return the data
        return HttpResponse(html_string)


class YaraRulesView(LoginRequiredMixin, TemplateView):
    """Manage Yara Rules"""
    def get(self, request, *args, **kwargs):
        template_name = 'viperweb/yara.html'
        rule_path = os.path.join(VIPER_ROOT, 'data/yara')
        rule_list = os.listdir(rule_path)
        # Read Rules

        action = request.GET.get('action')
        rule = request.GET.get('rule')
        rule_text = ''

        if action == 'list' or action is None:
            return render(request, template_name, {'rule_list': rule_list,
                                                   'rule_text': rule_text,
                                                   'projects': get_project_list()})
        elif action == 'display' and rule:
            # Display Rule Contents
            rule_file = os.path.join(rule_path, rule)
            if os.path.isfile(rule_file):
                # Only allow .yar or .yara files to be read
                file_name, file_ext = os.path.splitext(rule_file)
                if file_ext in ['.yar', '.yara']:
                    rule_text = open(rule_file, 'r').read()
                else:
                    rule_text = 'Invalid Rule File'
            else:
                rule_text = 'Invalid Rules File'

        elif action == 'delete':
            rule_name = request.GET.get('rulename')
            if rule_name.split('.')[-1] in ['yar', 'yara']:
                os.remove(os.path.join(rule_path, rule_name))
                rule_text = 'Rule {0} Deleted'.format(rule_name)
                # remove from list
                rule_list.remove(rule_name)
            else:
                rule_text = 'Invalid Rule'
            return render(request, template_name, {'rule_list': rule_list,
                                                   'rule_text': rule_text,
                                                   'projects': get_project_list()
                                                   })
        else:
            rule_text = 'Invalid Action'

        return render(request, template_name, {'rule_list': rule_list,
                                               'rule_name': rule,
                                               'rule_text': rule_text,
                                               'projects': get_project_list()})

    # Modify Rules
    def post(self, request, *args, **kwargs):
        template_name = 'viperweb/yara.html'

        rule_path = os.path.join(VIPER_ROOT, 'data/yara')
        rule_list = os.listdir(rule_path)

        rule_name = request.POST.get('rule_name')
        rule_text = request.POST.get('rule_text')
        rule_file = os.path.join(rule_path, rule_name)
        # Prevent storing files in a relative path or with a non yar extension
        rule_test = rule_name.split('.')
        if len(rule_test) == 2 and rule_test[-1] in ['yar', 'yara']:
            # if file exists overwrite
            with open(rule_file, 'w') as rule_edit:
                rule_edit.write(rule_text)
        else:
            rule_text = "The File Name did not match the style 'name.yar'"

        return render(request, template_name, {'rule_list': rule_list,
                                               'rule_name': rule_name,
                                               'rule_text': rule_text,
                                               'projects': get_project_list()})


class AboutView(TemplateView):
    """Show a simple about page"""
    def get(self, request, *args, **kwargs):
        template_name = "viperweb/about.html"

        return render(request, template_name, {'projects': get_project_list(),
                                               'extractors': Extractor().extractors})


class ChangelogView(TemplateView):
    """Show a simple changelog page"""
    def get(self, request, *args, **kwargs):
        template_name = "viperweb/changelog.html"

        _changelog = {"foo": "bar"}
        return render(request, template_name, {'changelog': _changelog,
                                               'projects': get_project_list()})


class CliView(LoginRequiredMixin, TemplateView):
    """Show GUI that implement the command line interface (CLI)"""
    def get(self, request, *args, **kwargs):
        project = kwargs.get("project", "default")
        if project not in get_project_list():
            raise Http404("unknown project: {}".format(project))

        template_name = "viperweb/cli.html"
        return render(request, template_name, {'project': project,
                                               'projects': get_project_list()})


class ConfigView(LoginRequiredMixin, TemplateView):
    """Show a simple page listing the settings from the config file"""
    def get(self, request, *args, **kwargs):
        template_name = "viperweb/config.html"

        sections = list(cfg.__dict__)
        config_values = {}
        for section in sections:
            config_values[section] = cfg.get(section)
        return render(request, template_name, {'config_values': config_values,
                                               'projects': get_project_list()})


class CreateProjectView(LoginRequiredMixin, TemplateView):
    """Create project (if not existing) and switch (redirect) to it"""
    def post(self, request, *args, **kwargs):
        project_name = request.POST['project'].replace(' ', '_')
        if project_name not in get_project_list():
            log.debug("creating new project: {}".format(project_name))

        log.debug("redirecting to project: {}".format(project_name))
        __project__.open(project_name)
        return redirect(reverse('main-page-project', kwargs={'project': project_name}))


class CuckooCheckOrSubmitView(LoginRequiredMixin, TemplateView):
    """Check if report for file exists on Cuckoo - if not submit"""
    def get(self, request, *args, **kwargs):
        project = kwargs.get("project", "default")
        if project not in get_project_list():
            raise Http404("unknown project: {}".format(project))

        sha256 = kwargs.get("sha256")
        if not sha256:
            log.error("no sha256 hashed provided")
            raise Http404("no sha256 hashed provided")

        # Open a session
        try:
            path = get_sample_path(sha256)
            __sessions__.new(path)
        except Exception as err:
            log.error("Error: {}".format(err))
            return HttpResponse('<span class="alert alert-danger">Invalid Submission</span>'.format())

        try:
            task_list_url = '{0}/tasks/list'.format(cfg.cuckoo.cuckoo_host)
            task_list_response = requests.get(task_list_url)
            if task_list_response.status_code == 200:
                task_list = task_list_response.json()
                task_list_filtered = [x for x in task_list["tasks"] if x["sample"]["sha256"] == sha256]
                if task_list_filtered:
                    task_list_filtered_sorted = sorted(task_list_filtered, key=itemgetter("added_on"), reverse=True)
                    task_id = task_list_filtered_sorted[0]["id"]
                    return HttpResponse('<a href="{0}/analysis/{1}/summary/" target="_blank"> Link to latest existing Cukoo Report</a>'.format(cfg.cuckoo.cuckoo_web, str(task_id)))
        except Exception as err:
            log.error("Error: {}".format(err))
            return HttpResponse('<span class="alert alert-danger">Error Connecting To Cuckoo</span>'.format())

        # If it doesn't exist, submit it.

        # Get the file data from viper
        file_data = open(__sessions__.current.file.path, 'rb').read()
        file_name = __sessions__.current.file.name

        if file_data:
            # Submit file data to cuckoo
            uri = '{0}{1}'.format(cfg.cuckoo.cuckoo_host, '/tasks/create/file')
            options = {'file': (file_name, file_data)}
            cuckoo_response = requests.post(uri, files=options)
            if cuckoo_response.status_code == 200:
                cuckoo_id = dict(cuckoo_response.json())['task_id']
                return HttpResponse('<a href="{0}/analysis/pending/" target="_blank"> Link To Cuckoo (pending tasks)</a>'.format(cfg.cuckoo.cuckoo_web, str(cuckoo_id)))
            else:
                log.error("Cuckoo Response Code: {}".format(cuckoo_response.status_code))

        return HttpResponse('<span class="alert alert-danger">Unable to Submit File</span>')


class SearchFileView(LoginRequiredMixin, TemplateView):
    """ Search file"""
    def post(self, request, *args, **kwargs):
        template_name = "viperweb/search.html"
        key = request.POST.get('key')
        value = request.POST.get('term').lower()
        curr_project = request.POST.get('curr_project')

        project_search = request.POST.get('project', False)

        print("Key: {}".format(key))
        print("Value: {}".format(value))

        # Set some data holders
        results = []
        projects = []

        # Search All Projects
        if project_search:
            # Get list of project paths
            projects = get_project_list()
        else:
            # If not searching all projects what are we searching
            projects.append(curr_project)

        # Search each Project in the list
        for project in projects:
            db = open_db(project)
            print(db)
            # get results
            proj_results = []
            rows = db.find(key=key, value=value)
            print(rows)

            for row in rows:
                proj_results.append([row.name, row.sha256])
            results.append({'name': project, 'res': proj_results})

        if results:
            # Return some things
            return render(request, template_name, {'results': results,
                                                   'projects': get_project_list()})
        else:
            return render(request, template_name, {'results': [],
                                                   'projects': get_project_list()})




# Template
# class IndexView(LoginRequiredMixin, TemplateView):
#     """Index View"""
#
#     def get(self, request, *args, **kwargs):
#         """get"""
#         template_name = "touren/index.html"
#
#         # messages.success(request, "success: Alles gut (Test)")
#         # messages.error(request, "error: Test Fehlermeldung")
#         return render(request, template_name, {})

