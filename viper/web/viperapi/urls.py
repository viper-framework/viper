# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from django.conf.urls import include, url
from django.views.generic import RedirectView
from rest_framework_nested import routers
from rest_framework_swagger.views import get_swagger_view

from . import views

app_name = 'viperapi_v3'

router = routers.DefaultRouter()
# project router
router.register(r'project', views.ProjectViewSet, basename="project")

# 1. level nested router: project/<pk>
project_router = routers.NestedSimpleRouter(router, r'project', lookup='project')

project_router.register(r'malware', views.MalwareViewSet, basename="malware")
project_router.register(r'tag', views.TagViewSet, basename="tag")
project_router.register(r'note', views.NoteViewSet, basename="note")
project_router.register(r'analysis', views.AnalysisViewSet, basename="analysis")

# 2. level nested router: project/<pk>/malware/<pk>
malware_router = routers.NestedSimpleRouter(project_router, r'malware', lookup='malware')

# 3. level nested for malware tags
malware_router.register(r'analysis', views.MalwareAnalysisViewSet, basename='malware-analysis')
malware_router.register(r'note', views.MalwareNoteViewSet, basename='malware-note')
malware_router.register(r'tag', views.MalwareTagViewSet, basename='malware-tag')

schema_view = get_swagger_view(title='Viper API v3')

urlpatterns = [
    # Main API route -> Redirect /api/ to /api/v3/project/
    url(r'^$', RedirectView.as_view(pattern_name='viperapi_v3:project-list'), name='redirect-to-api-v3'),

    # Extractors
    url(r'^v3/extractor/$', views.ExtractorAPIView.as_view(), name="extractor-list"),
    url(r'^v3/compressor/$', views.CompressorAPIView.as_view(), name="compressor-list"),
    url(r'^v3/module/$', views.ModuleAPIView.as_view(), name="module-list"),

    url(r'^v3/', include(router.urls)),
    url(r'^v3/', include(project_router.urls)),
    url(r'^v3/', include(malware_router.urls)),

    # Test Pages
    url(r'^v3/test/$', views.test, name='test'),
    url(r'^v3/test-auth/$', views.test_authenticated, name='test-auth'),

    # Docs (using Swagger)
    url(r'^v3/docs/', schema_view, name='api-docs'),
]
