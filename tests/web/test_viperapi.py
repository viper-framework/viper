# -*- coding: utf-8 -*-
from __future__ import unicode_literals
# import unittest

from django.test import TestCase
from django.utils.encoding import force_text

from django.contrib.auth.models import User

from rest_framework.authtoken.models import Token
from rest_framework.test import APIRequestFactory, APIClient

from viper.core.plugins import load_commands

# import requests
#
# from django.shortcuts import reverse
# from django.core.files.uploadedfile import SimpleUploadedFile
#
# from django.core.files import File
#
# from io import BytesIO

import os
import sys
# import pytest
from tests.conftest import FIXTURE_DIR

# from web.viperapi import views, serializers

try:
    from unittest import mock
except ImportError:
    # Python2
    import mock


class ViperAPIv3Test(TestCase):
    cmd = load_commands()

    def setUp(self):
        self.factory = APIRequestFactory()
        self.client = APIClient()
        self.user = User.objects.create_user('testuser', email='testuser@test.com', password='testing')
        self.user.save()
        token = Token.objects.create(user=self.user)
        token.save()

    def setup_method(self, method):
        """setUp by adding clean file"""
        # create api_test
        self.cmd['projects']['obj']('-s', 'api_test')
        self.cmd['open']['obj']('-f', os.path.join(FIXTURE_DIR, "chromeinstall-8u31.exe"))
        self.cmd['store']['obj']()

    def teardown_method(self, method):
        """clean all files"""
        self.cmd['projects']['obj']('-s', 'api_test')
        self.cmd['close']['obj']()

        if sys.version_info <= (3, 0):
            in_fct = 'builtins.raw_input'
        else:
            in_fct = 'builtins.input'
        with mock.patch(in_fct, return_value='y'):
            self.cmd['delete']['obj']('-a')

    def _require_login(self):
        self.client.login(username='testuser', password='testing')

    def test_api_root(self):
        # Issue a GET request and check response code
        response = self.client.get("/api/v3/")
        self.assertEqual(response.status_code, 200)

        # Check that the response content
        self.assertEqual(response.json()['project'], "http://testserver/api/v3/project/")
        self.assertJSONEqual(force_text(response.content), {"project": "http://testserver/api/v3/project/"})

    # TODO 2017-08-25 (frennkie) can't get this to run on Travis
    # def test_project_list_add(self):
    #     self._require_login()
    #
    #     self.maxDiff = None
    #
    #     # check list
    #     response = self.client.get("/api/v3/project/")
    #     self.assertEqual(response.status_code, 200)
    #
    #     # Check that the response content
    #     self.assertIsInstance(response.json()['results'], list)
    #     self.assertEqual(len(response.json()['results']), 5)
    #
    #     expected_json = {
    #         "count": 5,
    #         "next": None,
    #         "previous": None,
    #         "results": [
    #             {
    #                 "url": "http://testserver/api/v3/project/api_test/",
    #                 "data":
    #                     {"name": "api_test"}
    #             },
    #             {
    #                 'url': 'http://testserver/api/v3/project/project_switch_test1/',
    #                 'data':
    #                     {'name': 'project_switch_test1'},
    #             },
    #             {
    #                 'url': 'http://testserver/api/v3/project/copy_test_src/',
    #                 'data':
    #                     {'name': 'copy_test_src'},
    #             },
    #             {
    #                 'url': 'http://testserver/api/v3/project/copy_test_dst/',
    #                 'data':
    #                     {'name': 'copy_test_dst'},
    #             },
    #             {
    #                 "url": "http://testserver/api/v3/project/default/",
    #                 "data":
    #                     {"name": "default"}
    #             }
    #         ]
    #     }
    #
    #     self.assertJSONEqual(force_text(response.content), expected_json)
    #
    #     # now add
    #     response = self.client.post("/api/v3/project/", {"name": "api_test2"})
    #     self.assertEqual(response.status_code, 201)
    #
    #     # Check that the response content
    #     self.assertIsInstance(response.json()['data'], dict)
    #
    #     expected_json = {
    #         "data": {
    #             "name": "api_test2"
    #         },
    #         "url": "http://testserver/api/v3/project/api_test2/",
    #         "links": {
    #             "tags": "http://testserver/api/v3/project/api_test2/tag/",
    #             "malware": "http://testserver/api/v3/project/api_test2/malware/",
    #             "analysis": "http://testserver/api/v3/project/api_test2/analysis/",
    #             "notes": "http://testserver/api/v3/project/api_test2/note/"
    #         }
    #     }
    #
    #     self.assertJSONEqual(force_text(response.content), expected_json)
    #
    #     response = self.client.get("/api/v3/project/")
    #     self.assertEqual(len(response.json()['results']), 6)

    def test_default_project_detail(self):
        self._require_login()

        response = self.client.get("/api/v3/project/default/")
        self.assertEqual(response.status_code, 200)

        # Check that the response content
        self.assertIsInstance(response.json()['data'], dict)

        expected_json = {
            "data": {
                "name": "default"
            },
            "url": "http://testserver/api/v3/project/default/",
            "links": {
                "tags": "http://testserver/api/v3/project/default/tag/",
                "malware": "http://testserver/api/v3/project/default/malware/",
                "analysis": "http://testserver/api/v3/project/default/analysis/",
                "notes": "http://testserver/api/v3/project/default/note/",
                "web": "http://testserver/project/default/"
            }
        }

        self.assertJSONEqual(force_text(response.content), expected_json)

    def test_project_detail(self):
        self._require_login()

        response = self.client.get("/api/v3/project/api_test/")
        self.assertEqual(response.status_code, 200)

        expected_json = {
            "data": {
                "name": "api_test"
            },
            "url": "http://testserver/api/v3/project/api_test/",
            "links": {
                "tags": "http://testserver/api/v3/project/api_test/tag/",
                "malware": "http://testserver/api/v3/project/api_test/malware/",
                "analysis": "http://testserver/api/v3/project/api_test/analysis/",
                "notes": "http://testserver/api/v3/project/api_test/note/",
                "web": "http://testserver/project/api_test/"
            }
        }

        self.assertJSONEqual(force_text(response.content), expected_json)

    # Analysis: List all Analysis instances
    def test_analysis_list(self):
        self._require_login()

        response = self.client.get("/api/v3/project/api_test/analysis/")
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.json()['results'], list)
        self.assertEqual(len(response.json()['results']), 0)

        # self.assertEqual(response.json()['results'][0]['data']['cmd_line'], 'yara scan -t')
        # self.assertEqual(response.json()['results'][1]['data']['cmd_line'], 'triage')

    # Analysis: Retrieve an Analysis instance
    # def test_analysis_detail(self):
    #     self._require_login()
    #
    #     response = self.client.get("/api/v3/project/api_test/analysis/1/")
    #     self.assertEqual(response.status_code, 200)
    #     # self.assertEqual(response.json()['results']['data']['cmd_line'], 'yara scan -t')

    # Malware: List all Malware instances
    def test_malware_list(self):
        self._require_login()

        response = self.client.get("/api/v3/project/api_test/malware/")
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.json()['results'], list)
        self.assertEqual(len(response.json()['results']), 1)

        self.assertEqual(response.json()['results'][0]['data']['sha256'], '583a2d05ff0d4864f525a6cdd3bfbd549616d9e1d84e96fe145794ba0519d752')

    # Note: List all Note instances
    def test_note_list(self):
        self._require_login()

        response = self.client.get("/api/v3/project/api_test/note/")
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.json()['results'], list)
        self.assertEqual(len(response.json()['results']), 0)

    # Tag: List all Tag instances in project
    def test_tag_list(self):
        self._require_login()

        self.maxDiff = None

        response = self.client.get("/api/v3/project/api_test/tag/")
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.json()['results'], list)
        self.assertEqual(len(response.json()['results']), 0)

    # Tag: Add a new Tag to a Malware instance
    def test_malware_tag_add_remove(self):
        self._require_login()

        self.maxDiff = None

        response = self.client.get("/api/v3/project/api_test/malware/583a2d05ff0d4864f525a6cdd3bfbd549616d9e1d84e96fe145794ba0519d752/tag/")
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.json()['results'], list)
        self.assertEqual(len(response.json()['results']), 0)

        response = self.client.post("/api/v3/project/api_test/malware/583a2d05ff0d4864f525a6cdd3bfbd549616d9e1d84e96fe145794ba0519d752/tag/",
                                    {"tag": "foobar"})
        self.assertEqual(response.status_code, 201)

        expected_json = {
            "data": {
                "id": 1,
                "tag": "foobar"
            },
            "url": "http://testserver/api/v3/project/api_test/tag/1/"
        }

        self.assertJSONEqual(force_text(response.content), expected_json)

        response = self.client.delete("/api/v3/project/api_test/malware/583a2d05ff0d4864f525a6cdd3bfbd549616d9e1d84e96fe145794ba0519d752/tag/1/")
        self.assertEqual(response.status_code, 204)

    # def test_malware_list_add_update_delete(self):
    #     self._require_login()
    #
    #     self.maxDiff = None
    #
    #     # check list
    #     response = self.client.get("/api/v3/project/api_test/malware/")
    #     self.assertEqual(response.status_code, 200)
    #     self.assertIsInstance(response.json()['results'], list)
    #     self.assertEqual(len(response.json()['results']), 0)
    #
    #     # uploaded_file = SimpleUploadedFile(os.path.join(FIXTURE_DIR, "chromeinstall-8u31.exe"), b"file_content")
    #     # uploaded_file = SimpleUploadedFile(os.path.join(FIXTURE_DIR, "chromeinstall-8u31.exe"), "file_content", content_type="video/mp4")
    #
    #     # response = self.client.post("/api/v3/project/api_test/malware/upload/", {'file': uploaded_file})
    #
    #     # TODO(frennkie) this causes an error on __del__() or tempfile
    #     response = self.client.post("/api/v3/project/api_test/malware/upload/",
    #                                 {'file': open(os.path.join(FIXTURE_DIR, "chromeinstall-8u31.exe"), 'rb')})
    #
    #     self.assertEqual(response.status_code, 201)
    #
    #     response = self.client.get("/api/v3/project/api_test/malware/")
    #     self.assertEqual(response.status_code, 200)
    #     self.assertIsInstance(response.json()['results'], list)
    #     self.assertEqual(len(response.json()['results']), 1)
