# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

# Standard Imports
import os
from functools import wraps
import shutil
import tempfile

# Logging
import logging

# Django Imports
from django.shortcuts import HttpResponse
from django.utils.encoding import force_text
from django.core.files import File as DjangoFile

# DRF
from rest_framework import viewsets
from rest_framework import status
from rest_framework.parsers import FormParser, MultiPartParser, FileUploadParser
from rest_framework.compat import coreapi, coreschema
from rest_framework.filters import SearchFilter, OrderingFilter, BaseFilterBackend
from rest_framework.generics import ListAPIView
from rest_framework.mixins import ListModelMixin, CreateModelMixin, RetrieveModelMixin, UpdateModelMixin
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view, action, permission_classes
from rest_framework.exceptions import NotFound, ValidationError
from rest_framework.settings import api_settings

# SQL Alchemy
from sqlalchemy import or_
from sqlalchemy.orm import Session
from sqlalchemy.orm import subqueryload

# Serializers
from .serializers import ObjectSerializer
from .serializers import AnalysisSerializer, NoteSerializer, TagSerializer
from .serializers import MalwareAnalysisSerializer, MalwareNoteSerializer, MalwareTagSerializer
from .serializers import ProjectSerializer, ProjectListSerializer
from .serializers import PassSerializer
from .serializers import MalwareDownloadSerializer, MalwareUploadSerializer

# Viper imports
from viper.core.plugins import __modules__
from viper.core.project import __project__
from viper.core.project import get_project_list
from viper.common.objects import File
from viper.common.autorun import autorun_module
from viper.core.storage import store_sample, get_sample_path
from viper.core.database import Database, Malware, Tag, Note, Analysis
from viper.core.archiver import Compressor, Extractor
from viper.core.config import __config__

try:
    from scandir import walk  # noqa
except ImportError:
    from os import walk  # noqa

log = logging.getLogger("viper-web")
cfg = __config__

################
# API v3 (DRF) #
################


class SingleTermMultiFieldStartsWithSearchFilter(SearchFilter):
    def filter_queryset(self, request, queryset, view):
        search_fields = getattr(view, 'search_fields', None)
        search_terms = self.get_search_terms(request)

        if not search_fields or not search_terms:
            return queryset

        log.debug("Searching for \"{}\" in: {}".format(search_terms[0], search_fields))
        return queryset.filter(or_(*[(getattr(view.model, x).startswith(search_terms[0])) for x in search_fields]))


class FieldsFilter(BaseFilterBackend):
    def filter_queryset(self, request, queryset, view):
        return queryset

    def get_schema_fields(self, views):
        return [
            coreapi.Field(
                name="fields",
                required=False,
                location='query',
                schema=coreschema.String(
                    title='Cursor',
                    description=force_text("List of fields (comma separated) to be displayed. "
                                           "If empty all are shown. Can include _set fields.")
                )
            )
        ]


def get_project_open_db():
    """decorator: get project name from kwargs and open project database"""
    def my_decorator(func):
        @wraps(func)
        def func_wrapper(viewset, *args, **kwargs):
            log.debug("running decorator: get_project_open_db - called by: {}".format(viewset))

            project = viewset.kwargs.get(viewset.lookup_field_project, None)
            if project == 'default':
                __project__.open(project)
                db = Database()
            elif project in get_project_list():
                log.debug("setting project to: {}".format(project))
                __project__.open(project)
                db = Database()
            else:
                db = None

            if not db:
                error = {"error": {"code": "NotFound", "message": "Project not found: {}".format(project)}}
                log.error(error)
                raise NotFound(detail=error)

            return func(viewset, project=project, db=db, *args, **kwargs)
        return func_wrapper
    return my_decorator


class ExtractorAPIView(ListAPIView):
    """List available Archive Extractors"""
    queryset = [x.summary for (key, x) in Extractor().extractors.items()]
    serializer_class = PassSerializer


class CompressorAPIView(ListAPIView):
    """List available Archive Compressors"""
    queryset = [x.summary for (key, x) in Compressor().compressors.items()]
    serializer_class = PassSerializer


class ModuleAPIView(ListAPIView):
    """List available Modules"""
    queryset = [{"name": key, "description": value["description"]} for key, value in __modules__.items()]
    serializer_class = PassSerializer


class ViperGenericViewSet(ListModelMixin, RetrieveModelMixin, viewsets.GenericViewSet):
    """Generic View Set that implements common things that are required for accessing the SQLAlchemy models"""
    model = None
    serializer_class = None
    permission_classes = (IsAuthenticated,)

    lookup_field = 'id'
    lookup_field_project = 'project_name'

    @get_project_open_db()
    def get_object(self, project=None, db=None, *args, **kwargs):

        session = db.Session()
        obj = session.query(self.model).get(self.kwargs[self.lookup_field])
        if not obj:
            error = {"error": {"code": "NotFound",
                               "message": "{} not found ({}: {})".format(self.model.__name__,
                                                                         self.lookup_field,
                                                                         self.kwargs[self.lookup_field])}}
            raise NotFound(detail=error)
        return obj

    @get_project_open_db()
    def get_queryset(self, project=None, db=None, *args, **kwargs):

        session = db.Session()
        queryset = session.query(self.model)
        return queryset

    def get_serializer_context(self, *args, **kwargs):
        project = self.kwargs.get(self.lookup_field_project, None)
        context = dict()
        context["request"] = self.request
        context["project"] = project
        return context


class ViperGenericMalwareViewSet(ViperGenericViewSet):
    """Special customization for SQLAlchemy models that are directly tied to a malware instance (Analysis, Note, Tag)"""
    malware_relationship_field = None

    @get_project_open_db()
    def get_queryset(self, project=None, db=None, *args, **kwargs):
        malware_sha256 = self.kwargs["malware_sha256"]

        if malware_sha256:
            session = db.Session()
            malware = session.query(Malware).filter(Malware.sha256 == malware_sha256).one_or_none()

            if not malware:
                error = {"error": {"code": "NotFound",
                                   "message": "Malware not found: {} (Project: {})".format(malware_sha256, project)}}
                raise NotFound(detail=error)

            session = db.Session()

            malware = session.query(Malware) \
                .options(subqueryload(Malware.tag)) \
                .options(subqueryload(Malware.analysis)) \
                .options(subqueryload(Malware.note)).filter(Malware.sha256 == malware_sha256).one_or_none()

            queryset = getattr(malware, self.malware_relationship_field)

        else:
            session = db.Session()
            queryset = session.query(self.model)

        return queryset


class ProjectViewSet(ViperGenericViewSet, CreateModelMixin):
    """List and Retrieve Projects"""
    model = None
    serializer_class = ProjectSerializer  # list() overrides this

    lookup_field = 'name'  # this make sure that the URL keyword is project_name
    lookup_field_project = lookup_field

    @get_project_open_db()
    def get_object(self, project=None, db=None, *args, **kwargs):
        return project

    # @get_project_open_db()
    def get_queryset(self, project=None, db=None, *args, **kwargs):
        projects = get_project_list()
        if not next((i for i in projects if i == "default"), None):
            projects.append("default")  # make sure "default" is part of list of projects
        return projects

    def list(self, request, *args, **kwargs):
        """List all Projects"""
        self.serializer_class = ProjectListSerializer
        return super(ProjectViewSet, self).list(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        """Retrieve a Project"""
        return super(ProjectViewSet, self).retrieve(request, *args, **kwargs)

    def create(self, request, project=None, db=None, *args, **kwargs):
        """Create a new Project"""
        # kwargs provided by URLs/Routers: -

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        if serializer.validated_data['name'] in get_project_list():
            # exists already
            # return Response(data=serializer.validated_data, status=status.HTTP_200_OK)
            error = {"error": {"code": "ExistsAlready",
                               "message": "Project exists already: {}".format(serializer.validated_data['name'])}}
            raise ValidationError(detail=error)

        new_project_new = serializer.validated_data['name']

        __project__.open(new_project_new)

        serializer_new = self.get_serializer(new_project_new)
        headers = self.get_success_headers(serializer_new.data)

        return Response(data=serializer_new.data, status=status.HTTP_201_CREATED, headers=headers)


class MalwareViewSet(ViperGenericViewSet):
    """List and Retrieve Malware instances"""
    model = Malware
    serializer_class = ObjectSerializer
    lookup_field = 'sha256'

    filter_backends = (OrderingFilter, SingleTermMultiFieldStartsWithSearchFilter, FieldsFilter)
    ordering_fields = ('id',)  # '__all__' does not work!
    search_fields = ('name', 'md5', 'sha1', 'sha256', 'ssdeep')

    @get_project_open_db()
    def get_object(self, project=None, db=None, *args, **kwargs):
        session = db.Session()
        obj = session.query(self.model).filter(Malware.sha256 == self.kwargs[self.lookup_field]).one_or_none()
        if not obj:
            error = {"error": {"code": "NotFound",
                               "message": "{} not found ({}: {})".format(self.model.__name__,
                                                                         self.lookup_field,
                                                                         self.kwargs[self.lookup_field])}}
            raise NotFound(detail=error)

        return obj

    @get_project_open_db()
    def get_queryset(self, project=None, db=None, *args, **kwargs):
        session = db.Session()
        return session.query(self.model) \
            .options(subqueryload(Malware.tag)) \
            .options(subqueryload(Malware.analysis)) \
            .options(subqueryload(Malware.note))

    def list(self, request, *args, **kwargs):
        """List all Malware instances"""
        return super(MalwareViewSet, self).list(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        """Retrieve a Malware instance"""
        return super(MalwareViewSet, self).retrieve(request, *args, **kwargs)

    # Malware update makes no sense, or does it?
    # def update(self, request, *args, **kwargs):
    #     """Update a Malware instance"""
    #     return super(MalwareViewSet, self).update(request, *args, **kwargs)
    #
    # Malware update makes no sense, or does it?
    # def partial_update(self, request, *args, **kwargs):
    #     """Update a Malware instance (with partial data)"""
    #     return super(MalwareViewSet, self).partial_update(request, *args, **kwargs)

    @get_project_open_db()
    def destroy(self, request, project=None, db=None, *args, **kwargs):
        """Delete a Malware instance"""

        instance = self.get_object()

        try:
            log.debug("deleting (os.remove) Malware sample at path: {}".format(get_sample_path(instance.sha256)))
            os.remove(get_sample_path(instance.sha256))
        except OSError:
            log.error("failed to delete Malware sample: {}".format(get_sample_path(instance.sha256)))

        log.debug("deleting (db.delete_file) from DB for Malware ID: {}".format(instance.id))
        db.delete_file(instance.id)

        return Response(status=status.HTTP_204_NO_CONTENT)

    # TODO(frennkie) - this needs testing
    @action(detail=True, methods=['get', 'post'], serializer_class=MalwareDownloadSerializer)
    def download(self, request, *args, ** kwargs):
        """Download a Malware instance as a raw or compressed file"""
        # kwargs provided by URLs/Routers: project_name, sha256
        # malware_sha256 = self.kwargs.get("sha256", None)

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # get instance
        instance = self.get_object()
        dl_file = open(get_sample_path(instance.sha256), 'rb')

        # TODO(frennkie) encoding?!?! CLRF, LF ?! XXX
        response = HttpResponse(DjangoFile(dl_file), content_type=instance.mime)
        response['Content-Disposition'] = 'attachment; filename={}'.format(instance.name)
        return response

    @staticmethod
    def _process_uploaded(db, uploaded_file_path, file_name, tag_list=None, note_title=None, note_body=None):
        """_process_uploaded add one uploaded file to database and to storage then remove uploaded file"""

        log.debug("adding: {} as {}".format(uploaded_file_path, file_name))

        malware = File(uploaded_file_path)
        malware.name = file_name

        if get_sample_path(malware.sha256):
            error = {"error": {"code": "DuplicateFileHash",
                               "message": "File hash exists already: {} (sha256: {})".format(malware.name, malware.sha256)}}
            log.error("adding failed: {}".format(error))
            raise ValidationError(detail=error)  # TODO(frennkie) raise more specific error?! so that we can catch it..?!
        # Try to store file object into database
        if db.add(obj=malware, tags=tag_list):
            # If succeeds, store also in the local repository.
            # If something fails in the database (for example unicode strings)
            # we don't want to have the binary lying in the repository with no
            # associated database record.
            malware_stored_path = store_sample(malware)

            # run autoruns on the stored sample
            if cfg.get('autorun').enabled:
                autorun_module(malware.sha256)

            log.debug("added file \"{0}\" to {1}".format(malware.name, malware_stored_path))

            if note_body and note_title:
                db.add_note(malware.sha256, note_title, note_body)
                log.debug("added note: \"{0}\"".format(note_title))

        else:
            error = {"error": {"code": "DatabaseAddFailed",
                               "message": "Adding File to Database failed: {} (sha256: {})".format(malware.name, malware.sha256)}}
            log.error("adding failed: {}".format(error))
            raise ValidationError(detail=error)

        # clean up
        try:
            os.remove(uploaded_file_path)
        except OSError as err:
            log.error("failed to delete temporary file: {}".format(err))

        return malware

    # TODO(frennkie) - this needs testing and cleaning up!
    @get_project_open_db()
    @action(detail=False, methods=['post'],
            serializer_class=MalwareUploadSerializer,
            parser_classes=[MultiPartParser, FormParser, FileUploadParser])
    def upload(self, request, project=None, db=None, *args, ** kwargs):
        """Upload file as new Malware instance"""
        session = db.Session()

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        log.debug("Validated Data: {}".format(serializer.validated_data))
        store_archive = serializer.validated_data.get("store_archive", None)
        archive_pass = serializer.validated_data.get("archive_pass", None)
        extractor = serializer.validated_data.get("extractor", None)
        tag_list = serializer.validated_data.get("tag_list", None)
        note_title = serializer.validated_data.get("note_title", None)
        note_body = serializer.validated_data.get("note_body", None)
        uploaded_files = serializer.validated_data.get("file", None)
        uploaded_file_name = serializer.validated_data.get("file_name", None)

        to_process = list()
        tmp_dirs = list()

        for uploaded_file in uploaded_files:
            log.debug("Working on: {}".format(uploaded_file))

            # if a file name was provided (to override name of uploaded file) then us it
            uploaded_file_path = uploaded_file.temporary_file_path()
            log.debug("Working on (Path): {}".format(uploaded_file_path))

            if not uploaded_file_name:
                uploaded_file_name = "{}".format(uploaded_file)

            if extractor:
                log.debug("Extractor: {}".format(extractor))

                if extractor == "auto":
                    tmp_dir = tempfile.mkdtemp(prefix="viper_tmp_")
                    tmp_dirs.append(tmp_dir)
                    new_uploaded_file = os.path.join(tmp_dir, uploaded_file_name)
                    # os.rename(uploaded_file_path, new_uploaded_file)  # TODO(frennkie) renaming causes Django to raise an error because it can't delete tmp file
                    shutil.copy(uploaded_file_path, new_uploaded_file)  # TODO(frennkie) copying temporay file seems a bit wasteful (I/O, disk space)

                    ext = Extractor()

                    _, uploaded_file_extension = ext.auto_discover_ext(new_uploaded_file)
                    if uploaded_file_extension in ext.extensions:
                        res = ext.extract(archive_path=new_uploaded_file, password=archive_pass)
                    else:
                        to_process.append((new_uploaded_file, uploaded_file_name))
                        continue

                else:
                    new_uploaded_file = uploaded_file_path
                    ext = Extractor()
                    res = ext.extract(archive_path=new_uploaded_file, cls_name=extractor, password=archive_pass)

                if res:
                    log.debug("Extract Result: {} - Path: {}".format(res, ext.output_path))
                    if not os.path.isdir(ext.output_path):
                        # make sure to only add directories to tmp_dirs list
                        ext.output_path = os.path.dirname(ext.output_path)
                    tmp_dirs.append(ext.output_path)

                    for dir_name, dir_names, file_names in walk(ext.output_path):
                        # Add each collected file.
                        for file_name in file_names:
                            to_process.append((os.path.join(dir_name, file_name), file_name))

                    if store_archive:
                        log.debug("need to store the Archive too")
                        to_process.insert(0, (new_uploaded_file, os.path.basename(new_uploaded_file)))
                        # TODO(frennkie) Parent Child relation?!

                else:
                    log.debug("Extract Result: {}".format(res))
                    # TODO(frennkie) raise?!

            else:
                log.debug("No Extractor will be used, just store uploaded file")
                if uploaded_file_name:
                    to_process.append((uploaded_file_path, uploaded_file_name))

                else:
                    to_process.append((uploaded_file_path, "{}".format(uploaded_file)))

            # reset uploaded_file_name
            uploaded_file_name = None

        processed = list()
        for item in to_process:
            processed.append(self._process_uploaded(db, item[0], item[1], tag_list, note_title, note_body))  # TODO(frennkie) Error handling (e.g. duplicate hashes?!)

        log.debug("Tmp Dirs: {}".format(tmp_dirs))
        for item in tmp_dirs:
            try:
                shutil.rmtree(item)
            except OSError as err:
                log.error("failed to delete temporary dir: {}".format(err))

        if not len(processed):
            log.error("failed..")
            raise Exception("Something went wrong")

        elif len(processed) == 1:
            obj = session.query(Malware).filter(Malware.sha256 == processed[0].sha256).one_or_none()
            serializer = self.get_serializer([obj], many=True)
            headers = self.get_success_headers(serializer.data)
            return Response(serializer.data, status=201, headers=headers)
        else:
            obj_list = [session.query(Malware).filter(Malware.sha256 == x.sha256).one_or_none() for x in processed]
            serializer = self.get_serializer(obj_list, many=True)
            headers = self.get_success_headers(serializer.data)
            return Response(serializer.data, status=201, headers=headers)

    def get_success_headers(self, data):
        log.debug("Success Headers")
        log.debug("Data: {}".format(data))
        log.debug("Api Settings: {}".format(api_settings.URL_FIELD_NAME))
        log.debug("Final: {}".format(data[0][api_settings.URL_FIELD_NAME]))
        try:
            # TODO(frennkie) only return Location for first uploaded file (even if multiple)
            return {'Location': data[0][api_settings.URL_FIELD_NAME]}
        except (TypeError, KeyError):
            return {}


class TagViewSet(ViperGenericViewSet, UpdateModelMixin):
    """List and Retrieve Tag instances"""
    model = Tag
    serializer_class = TagSerializer

    filter_backends = (OrderingFilter, SingleTermMultiFieldStartsWithSearchFilter, FieldsFilter)
    ordering_fields = ('id',)  # '__all__' does not work!
    search_fields = ('tag',)

    def list(self, request, *args, **kwargs):
        """List all Tag instances in project"""
        return super(TagViewSet, self).list(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        """Retrieve a Tag instance"""
        return super(TagViewSet, self).retrieve(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        """Update a Tag instance (project wide)"""
        return super(TagViewSet, self).update(request, *args, **kwargs)

    def partial_update(self, request, *args, **kwargs):
        """Update a Tag instance (with partial data - project wide)"""
        return super(TagViewSet, self).partial_update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        """Delete a Tag instance (project wide)"""
        instance = self.get_object()
        session = Session.object_session(instance)
        session.delete(instance)
        session.commit()

        return Response(status=status.HTTP_204_NO_CONTENT)


class MalwareTagViewSet(ViperGenericMalwareViewSet, TagViewSet, CreateModelMixin):
    """List and Retrieve Tag (for Malware) instances"""
    malware_relationship_field = "tag"
    serializer_class = MalwareTagSerializer

    def list(self, request, *args, **kwargs):
        """List all Tag instances for an Malware instance"""
        return super(MalwareTagViewSet, self).list(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        """Retrieve a Tag instance for an Malware instance"""
        return super(MalwareTagViewSet, self).retrieve(request, *args, **kwargs)

    @get_project_open_db()
    def create(self, request, project=None, db=None, *args, **kwargs):
        """Add a new Tag to a Malware instance"""
        # kwargs provided by URLs/Routers: project_name, malware_sha256
        malware_sha256 = self.kwargs["malware_sha256"]

        session = db.Session()
        malware = session.query(Malware).filter(Malware.sha256 == malware_sha256).one_or_none()
        if not malware:
            error = {"error": {"code": "NotFound",
                               "message": "Malware not found: {} (Project: {})".format(malware_sha256, project)}}
            raise NotFound(detail=error)

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        new_tag = serializer.validated_data['tag']
        log.debug("I will now add tag: {} to Malware: {}".format(new_tag, malware))
        db.add_tags(malware.sha256, new_tag)  # add_tags expects a list of tags

        obj = session.query(self.model).filter(Tag.tag == new_tag[0]).one_or_none()  # TODO(frennkie) new_tag[0] ..?! this now create multiple

        serializer_new = self.get_serializer(obj)
        headers = self.get_success_headers(serializer_new.data)

        return Response(data=serializer_new.data, status=status.HTTP_201_CREATED, headers=headers)

    @get_project_open_db()
    def destroy(self, request, project=None, db=None, *args, **kwargs):
        """Delete a Tag from a Malware/File"""
        # kwargs provided by URLs/Routers: project_name, malware_sha256, id
        malware_sha256 = self.kwargs["malware_sha256"]
        tag_id = self.kwargs["id"]

        session = db.Session()

        tag = session.query(self.model).get(tag_id)
        if not tag:
            error = {"error": {"code": "NotFound",
                               "message": "Tag not found: {} (Project: {})".format(tag_id, project)}}
            raise NotFound(detail=error)

        if not tag.malware:
            log.error("Tag: {} not related to any Malware - will remove it".format(tag))
            try:
                session.delete(tag)
                session.commit()
                return Response(status=status.HTTP_204_NO_CONTENT)
            except Exception as err:
                log.error("Tag: {} problem".format(tag, err))

        malware = session.query(Malware).filter(Malware.sha256 == malware_sha256).one_or_none()
        if not malware:
            error = {"error": {"code": "NotFound",
                               "message": "Malware not found: {} (Project: {})".format(malware_sha256, project)}}
            raise NotFound(detail=error)

        if tag not in malware.tag:
            error = {"error": {"code": "NotFound",
                               "message": "Tag {}: {} is not associated to Malware: {} (Project: {})".format(tag.id, tag.tag, malware.sha256, project)}}
            raise NotFound(detail=error)

        log.info("I will now delete tag: {} (from Malware: {})".format(tag, malware))
        db.delete_tag(tag.tag, malware.sha256)
        return Response(status=status.HTTP_204_NO_CONTENT)


class NoteViewSet(ViperGenericViewSet):
    """List and Retrieve Note instances"""
    model = Note
    serializer_class = NoteSerializer

    filter_backends = (OrderingFilter, SingleTermMultiFieldStartsWithSearchFilter, FieldsFilter)
    ordering_fields = ('id',)  # '__all__' does not work!
    search_fields = ('title', 'body')

    def list(self, request, *args, **kwargs):
        """List all Note instances"""
        return super(NoteViewSet, self).list(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        """Retrieve a Note instance"""
        return super(NoteViewSet, self).retrieve(request, *args, **kwargs)


class MalwareNoteViewSet(ViperGenericMalwareViewSet, NoteViewSet, UpdateModelMixin, CreateModelMixin):
    """List and Retrieve Note (for Malware) instances"""
    malware_relationship_field = "note"
    serializer_class = MalwareNoteSerializer

    def list(self, request, *args, **kwargs):
        """List all Note instances for an Malware instance"""
        return super(MalwareNoteViewSet, self).list(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        """Retrieve a Note instance for an Malware instance"""
        return super(MalwareNoteViewSet, self).retrieve(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        """Update a Note instance"""
        return super(MalwareNoteViewSet, self).update(request, *args, **kwargs)

    def partial_update(self, request, *args, **kwargs):
        """Update a Note instance (with partial data)"""
        return super(MalwareNoteViewSet, self).partial_update(request, *args, **kwargs)

    @get_project_open_db()
    def create(self, request, project=None, db=None, *args, **kwargs):
        """Add a new Note to a Malware instance"""
        # kwargs provided by URLs/Routers: project_name, malware_sha256
        malware_sha256 = self.kwargs["malware_sha256"]

        session = db.Session()
        malware = session.query(Malware).filter(Malware.sha256 == malware_sha256).one_or_none()
        if not malware:
            error = {"error": {"code": "NotFound",
                               "message": "Malware not found: {} (Project: {})".format(malware_sha256, project)}}
            raise NotFound(detail=error)

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        new_title = serializer.validated_data['title']
        new_body = serializer.validated_data['body']
        log.debug("I will now add Note: {} to Malware: {}".format(new_title, malware))
        db.add_note(malware.sha256, new_title, new_body)

        try:
            new_note_id = db.added_ids.get("note")[0]
            log.debug("new Note created: {}".format(new_note_id))
        except (TypeError, IndexError):
            raise Exception("No new Note created")

        obj = session.query(self.model).get(new_note_id)

        serializer_new = self.get_serializer(obj)
        headers = self.get_success_headers(serializer_new.data)

        return Response(data=serializer_new.data, status=status.HTTP_201_CREATED, headers=headers)

    def destroy(self, request, *args, **kwargs):
        """Delete a Note instance"""
        instance = self.get_object()
        session = Session.object_session(instance)
        session.delete(instance)
        session.commit()

        return Response(status=status.HTTP_204_NO_CONTENT)


class AnalysisViewSet(ViperGenericViewSet):
    """List and Retrieve Analysis instances"""
    model = Analysis
    serializer_class = AnalysisSerializer

    filter_backends = (OrderingFilter, SingleTermMultiFieldStartsWithSearchFilter, FieldsFilter)
    ordering_fields = ('id',)  # '__all__' does not work!
    search_fields = ('cmd_line',)

    def list(self, request, *args, **kwargs):
        """List all  Analysis instances"""
        return super(AnalysisViewSet, self).list(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        """Retrieve an Analysis instance"""
        return super(AnalysisViewSet, self).retrieve(request, *args, **kwargs)


class MalwareAnalysisViewSet(ViperGenericMalwareViewSet, AnalysisViewSet):
    """List and Retrieve Analysis (for Malware) instances"""
    malware_relationship_field = "analysis"
    serializer_class = MalwareAnalysisSerializer

    def list(self, request, *args, **kwargs):
        """List all Analysis instances for an Malware instance"""
        return super(MalwareAnalysisViewSet, self).list(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        """Retrieve a Analysis instance for an Malware instance"""
        return super(MalwareAnalysisViewSet, self).retrieve(request, *args, **kwargs)

    # Updating an Analysis doesn't make much sense!
    # def update(self, request, *args, **kwargs):
    #     """Update an Analysis"""
    #     return super(MalwareAnalysisViewSet, self).update(request, *args, **kwargs)

    # Updating an Analysis doesn't make much sense!
    # def partial_update(self, request, *args, **kwargs):
    #     """Update an Analysis (with partial data)"""
    #     return super(MalwareAnalysisViewSet, self).partial_update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        """Delete an Analysis instance"""
        instance = self.get_object()
        session = Session.object_session(instance)
        session.delete(instance)
        session.commit()

        return Response(status=status.HTTP_204_NO_CONTENT)


@api_view(['GET', 'POST'])
def test(request):
    """Test GET and POST API (**no** authentication)"""
    if request.method == 'POST':
        return Response({"message": "Got some data! (Authentication has not been checked)", "data": request.data})
    return Response({"message": "Hello Anonymous! (Authentication has not been checked)"})


@api_view(['GET', 'POST'])
@permission_classes((IsAuthenticated,))
def test_authenticated(request):
    """Test GET and POST API (authentication **required**)"""
    if request.method == 'POST':
        return Response({"message": "Got some data! (Authentication validated successfully)", "data": request.data})
    return Response({"message": "Hello {}! (Authentication validated successfully)".format(request.user)})

# TODO(frennkie) check whether and how to run modules

#
# @route('/modules/run', method='POST')
# def run_module():
#     project = request.forms.get('project')
#     sha256 = request.forms.get('sha256')
#     cmd_line = request.forms.get('cmdline')
#
#     if project:
#         __project__.open(project)
#     else:
#         __project__.open('../')
#
#     if sha256:
#         file_path = get_sample_path(sha256)
#         if file_path:
#             __sessions__.new(file_path)
#
#     if not cmd_line:
#         response.code = 404
#         return {'message': 'Invalid command line'}
#
#     results = module_cmdline(cmd_line, sha256)
#     __sessions__.close()
#
#     return {"results": results}
#
#
# def module_cmdline(cmd_line, sha256):
#     # TODO: refactor this function, it has some ugly code.
#     command_outputs = []
#     cmd = Commands()
#     split_commands = cmd_line.split(';')
#     for split_command in split_commands:
#         split_command = split_command.strip()
#         if not split_command:
#             continue
#         args = []
#         # Split words by white space.
#         words = split_command.split()
#         # First word is the root command.
#         root = words[0]
#         # If there are more words, populate the arguments list.
#         if len(words) > 1:
#             args = words[1:]
#         try:
#             if root in cmd.commands:
#                 cmd.commands[root]['obj'](*args)
#                 if cmd.output:
#                     command_outputs += cmd.output
#                 del(cmd.output[:])
#             elif root in __modules__:
#                 # if prev commands did not open a session open one
#                 # on the current file
#                 if sha256:
#                     path = get_sample_path(sha256)
#                     __sessions__.new(path)
#                 module = __modules__[root]['obj']()
#                 module.set_commandline(args)
#                 module.run()
#
#                 command_outputs += module.output
#                 print(type(module.output))
#                 del(module.output[:])
#             else:
#                 command_outputs.append({'message': '{0} is not a valid command'.format(cmd_line)})
#         except:
#             command_outputs.append({'message': 'Unable to complete the command: {0}'.format(cmd_line)})
#     __sessions__.close()
#     return command_outputs
