# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from django.conf.urls import url
from django.contrib.auth.views import login, logout

from . import views
from .forms import MyAuthenticationForm

urlpatterns = [
    # Main Page
    url(r'^$', views.main_page, name='main_page'),


    url(r'^accounts/login/$', login,
        {'template_name': 'viperweb/user_login.html', 'authentication_form': MyAuthenticationForm}, name='login'),
    url(r'^accounts/logout/$', logout,
        {'template_name': 'viperweb/logged_out.html'}, name='logout'),

    # Project Page (Main view)
    url(r'^project/(?P<project>.+)/$', views.main_page, name='main-page-project'),

    # Changelog Page
    url(r'^changelog/', views.changelog, name='changelog'),

    # About Page
    url(r'^about/', views.about, name='about'),

    # File Page
    url(r'^file/(?P<project>.+)/(?P<sha256>[^/]+)/$', views.file_view, name='file-view'),
    url(r'^file/(?P<project>.+)/$', views.file_view, name='file-list'),

    # Hex
    url(r'^hex/$', views.hex_view, name='hex-view'),

    # Module Ajax
    url(r'^module/$', views.run_module, name='run-module'),

    # Yara
    url(r'^yara/$', views.yara_rules, name='yara-rules'),

    # Create Project
    url(r'^create/$', views.create_project, name='create-project'),


    # Upload from URL
    url(r'^urldownload/', views.url_download, name='url-download'),

    # Config File
    url(r'^config/$', views.config_file, name='config-file'),

    # Search
    url(r'^search/$', views.search_file, name='search-file'),
]
