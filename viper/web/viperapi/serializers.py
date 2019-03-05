# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

# make str() work on both Py2 and Py3
from builtins import str

from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from rest_framework.reverse import reverse

from sqlalchemy.orm import Session
from viper.core.database import Malware, Tag, Note, Analysis
from viper.core.archiver import Compressor, Extractor

tables = (Malware, Tag, Note, Analysis)


class ObjectSerializer(serializers.Serializer):
    """
    A read-only serializer that coerces objects into primitive representations.
    """

    def validate(self, data):
        # include csrfmiddlewaretoken in the expected fields (QueryDict)
        expected_fields = list(self.fields)
        expected_fields.append("csrfmiddlewaretoken")

        unknown_keys = list(set(list(self.initial_data)) - set(expected_fields))
        if unknown_keys:
            raise ValidationError("Got unknown fields: {}".format(unknown_keys))
        return data

    # def to_internal_value(self, data):
    #     pass

    def to_representation(self, obj, recurse=True):
        """implement to_representation"""

        data = dict()
        ret = dict()

        # if fields is None all attributes will be returned
        # if fields is set then only those attributes will be included
        fields = self.context["request"].query_params.get("fields", None)

        # build url to have a nice browseable view in DRF
        if isinstance(obj, Malware):
            url = reverse("viperapi_v3:malware-detail",
                          kwargs={"project_name": self.context["project"], "sha256": obj.sha256},
                          request=self.context["request"])
            links = dict()
            links.update({"analysis": reverse("viperapi_v3:malware-analysis-list",
                                              kwargs={"project_name": self.context["project"], "malware_sha256": obj.sha256},
                                              request=self.context["request"])})
            links.update({"notes": reverse("viperapi_v3:malware-note-list",
                                           kwargs={"project_name": self.context["project"], "malware_sha256": obj.sha256},
                                           request=self.context["request"])})
            links.update({"tags": reverse("viperapi_v3:malware-tag-list",
                                          kwargs={"project_name": self.context["project"], "malware_sha256": obj.sha256},
                                          request=self.context["request"])})
            links.update({"web": reverse("file-view", kwargs={"project": self.context["project"], "sha256": obj.sha256},
                                         request=self.context["request"])})
            ret.update({"links": links})
        else:
            detail_url_name = "viperapi_v3:{}-detail".format(obj.__class__.__table__)
            url = reverse(detail_url_name,
                          kwargs={"project_name": self.context["project"], "id": obj.id},
                          request=self.context["request"])

        for attribute_name in dir(obj):
            attribute = getattr(obj, attribute_name)
            if attribute_name.startswith("_"):
                # ignore private attributes
                pass
            elif attribute_name in ["metadata"]:
                # ignore some defined attributes
                pass
            elif hasattr(attribute, '__call__'):
                # ignore methods and other callables
                pass
            elif isinstance(attribute, (str, int, bool, float, type(None))):
                # Primitive types can be passed through unmodified.
                if not fields:
                    data[attribute_name] = attribute
                elif attribute_name in fields:
                    data[attribute_name] = attribute
            elif isinstance(attribute, list):
                if not recurse:
                    continue  # skip lists when not recursing

                if not attribute:
                    continue  # skip empty lists

                if not isinstance(attribute[0], tables):
                    # print("skipping list of non table objects: {}".format(attribute[0]))
                    continue

                set_name = "{}_set".format(attribute[0].__class__.__table__)
                if not fields:
                    data[set_name] = [self.to_representation(item, recurse=False)
                                      for item in attribute]
                elif set_name in fields:
                    data[set_name] = [self.to_representation(item, recurse=False)
                                      for item in attribute]

            elif isinstance(attribute, dict):
                if not recurse:
                    continue  # skip dicts when not recursing

                if not attribute:
                    continue  # skip empty dicts

                # TODO(frennkie) this is not tested
                if not fields:
                    data[attribute_name] = {
                        str(key): self.to_representation(value)
                        for key, value in attribute.items()
                    }
                elif attribute_name in fields:
                    data[attribute_name] = {
                        str(key): self.to_representation(value)
                        for key, value in attribute.items()
                    }
            else:
                # Force anything else to its string representation.
                if not fields:
                    data[attribute_name] = str(attribute)
                elif attribute_name in fields:
                    data[attribute_name] = str(attribute)

        ret.update({"url": url})
        ret.update({"data": data})

        return ret

    def update(self, instance, validated_data):
        """Generic implementation of update - override if needed"""
        session = Session.object_session(instance)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        session.commit()

        return instance

    def create(self, validated_data):  # implementing create is required
        pass


class TagSerializer(ObjectSerializer):
    """TagSerializer"""
    model = Tag

    id = serializers.IntegerField(required=False, read_only=True)
    tag = serializers.CharField(max_length=255, required=True)

    # tags are stored lower case
    def validate_tag(self, value):
        if not value == value.lower():
            raise serializers.ValidationError("has to be all lower case")
        if " " in value:
            raise serializers.ValidationError("spaces are not allowed")
        tag_list = value.strip().split(",")
        return tag_list

    def update(self, instance, validated_data):
        """validated data on Tag is a list - only use first list item for update"""
        session = Session.object_session(instance)

        for attr, value in validated_data.items():
            setattr(instance, attr, value[0])
        session.commit()

        return instance

    def create(self, validated_data):
        pass


class MalwareTagSerializer(TagSerializer):
    """MalwareTagSerializer"""

    def to_representation(self, obj, recurse=True):
        return super(MalwareTagSerializer, self).to_representation(obj, recurse=False)


class NoteSerializer(ObjectSerializer):
    """NoteSerializer"""
    model = Note

    id = serializers.IntegerField(required=False, read_only=True)
    title = serializers.CharField(max_length=255, required=True)
    body = serializers.CharField(required=True, allow_blank=True)

    def create(self, validated_data):
        pass


class MalwareNoteSerializer(NoteSerializer):
    """MalwareNoteSerializer"""
    def to_representation(self, obj, recurse=True):
        return super(MalwareNoteSerializer, self).to_representation(obj, recurse=False)


class AnalysisSerializer(ObjectSerializer):
    """AnalysisSerializer"""
    model = Analysis

    id = serializers.IntegerField(required=False, read_only=True)
    cmd_line = serializers.CharField(max_length=255, required=True)
    results = serializers.CharField(required=True, allow_blank=True)
    stored_at = serializers.DateTimeField(read_only=True)

    def create(self, validated_data):
        pass


class MalwareAnalysisSerializer(AnalysisSerializer):
    """MalwareAnalysisSerializer"""
    def to_representation(self, obj, recurse=True):
        return super(MalwareAnalysisSerializer, self).to_representation(obj, recurse=False)


class PassSerializer(serializers.Serializer):
    def to_representation(self, obj):
        return obj

    def update(self, instance, validated_data):
        pass

    def create(self, validated_data):
        pass


class ProjectSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=255)

    def to_representation(self, obj):
        return {
            "url": reverse("viperapi_v3:project-detail", kwargs={"name": obj}, request=self.context["request"]),
            'data': {
                'name': obj
            },
            'links': {
                "analysis": reverse("viperapi_v3:analysis-list", kwargs={"project_name": obj}, request=self.context["request"]),
                "malware": reverse("viperapi_v3:malware-list", kwargs={"project_name": obj}, request=self.context["request"]),
                "notes": reverse("viperapi_v3:note-list", kwargs={"project_name": obj}, request=self.context["request"]),
                "tags": reverse("viperapi_v3:tag-list", kwargs={"project_name": obj}, request=self.context["request"]),
                "web": reverse("main-page-project", kwargs={"project": obj}, request=self.context["request"])
            }
        }

    def update(self, instance, validated_data):
        pass

    def create(self, validated_data):
        pass


class ProjectListSerializer(ProjectSerializer):
    def to_representation(self, obj):
        return {
            "url": reverse("viperapi_v3:project-detail", kwargs={"name": obj}, request=self.context["request"]),
            'data': {'name': obj}}


class MalwareDownloadSerializer(ObjectSerializer):
    """MalwareDownloadSerializer"""
    model = Malware

    compressor = serializers.CharField(max_length=255, required=False)
    password = serializers.CharField(max_length=255, required=False)

    def validate_compressor(self, value):
        compressors = list(Compressor().compressors)
        if value not in compressors:
            raise serializers.ValidationError("{}: not in list of supported Compressors: {}".format(value, compressors))
        return value

    def create(self, validated_data):
        pass


class MalwareUploadSerializer(ObjectSerializer):
    """MalwareUploadSerializer"""
    model = Malware

    extractor = serializers.CharField(max_length=255, required=False, label="Extractor", help_text="which Extractor implementation to use (auto: Auto-detect; none: No Extractor)")
    tag_list = serializers.CharField(max_length=1000, required=False, label="Tags", help_text="comma separated, all lowercase, no spaces")
    archive_pass = serializers.CharField(max_length=255, required=False, label="Password", help_text="archive extract password")
    store_archive = serializers.CharField(max_length=100, required=False, label="Store Archive", help_text="store or discard archive after extract")
    note_title = serializers.CharField(max_length=100, required=False, label="Note Title", help_text="title of note to be added")
    note_body = serializers.CharField(max_length=1000, required=False, label="Note Body", help_text="body to note to be added ")

    # allow multiple files
    file = serializers.ListField(child=serializers.FileField(max_length=255, required=True, allow_empty_file=False))
    file_name = serializers.CharField(max_length=255, required=False, label="File Name", help_text="override file name of uploaded file")

    def validate(self, data):
        if len(data.get("file", None)) > 1 and data.get("file_name", None):
            raise serializers.ValidationError("can not provide file_name when uploading multiple files")
        return data

    def validate_file_name(self, value):
        print("File Name: {} ({})".format(value, type(value)))
        return value

    def validate_file(self, value):
        print("File: {} ({})".format(value, type(value)))
        return value

    def validate_extractor(self, value):
        # convert "none"/"false" strings into Python None
        if value in ["none", "None", "NONE", "false", "False", "FALSE"]:
            return None

        # auto detect is a valid option
        if value in ["auto", "Auto", "AUTO"]:
            return "auto"

        # if neither none nor auto then check whether selected Extractor is supported/available
        extractors = (Extractor().extractors)
        if value not in extractors:
            raise serializers.ValidationError("{}: not in list of supported Extractors: {}".format(value, extractors))

        return value

    def validate_store_archive(self, value):
        if value.lower() == "true":
            return True
        elif value.lower() == "false":
            return False
        else:
            raise serializers.ValidationError("must be either true or false")

    # tag_list expects a comma separated list of tags (tags are always all lowercase)
    def validate_tag_list(self, value):
        if not value == value.lower():
            raise serializers.ValidationError("has to be all lower case")
        if " " in value:
            raise serializers.ValidationError("spaces are not allowed")
        tag_list = value.strip().split(",")
        return tag_list

    def create(self, validated_data):
        pass
