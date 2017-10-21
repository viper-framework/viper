# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from django.conf.urls import url
from django.contrib.auth.views import login, logout

from . import views
from .forms import MyAuthenticationForm

urlpatterns = [
    # login/logout (accounts)
    url(r'^accounts/login/$', login,
        {'template_name': 'viperweb/user_login.html', 'authentication_form': MyAuthenticationForm}, name='login'),
    url(r'^accounts/logout/$', logout,
        {'template_name': 'viperweb/logged_out.html'}, name='logout'),

    # Main Page
    url(r'^$', views.MainPageView.as_view(), name='main_page'),
    url(r'^project/(?P<project>[^/]+)/$', views.MainPageView.as_view(), name='main-page-project'),  # Project Page (Main view)

    url(r'^about/', views.AboutView.as_view(), name='about'),
    url(r'^changelog/', views.ChangelogView.as_view(), name='changelog'),
    url(r'^cli/', views.CliView.as_view(), name='cli'),
    url(r'^config/$', views.ConfigView.as_view(), name='config-file'),
    url(r'^create/$', views.CreateProjectView.as_view(), name='create-project'),

    url(r'^project/(?P<project>[^/]+)/file/(?P<sha256>[^/]+)/$', views.FileView.as_view(), name='file-view'),  # File Page
    url(r'^project/(?P<project>[^/]+)/file/$', views.FileView.as_view(), name='file-list'),  # File List

    url(r'^project/(?P<project>[^/]+)/file/(?P<sha256>[^/]+)/cuckoo/$', views.CuckooCheckOrSubmitView.as_view(), name='file-cuckoo-submit'),

    url(r'^hex/$', views.HexView.as_view(), name='hex-view'),  # Hex
    url(r'^module/$', views.RunModuleView.as_view(), name='run-module'),  # Module Ajax
    url(r'^search/$', views.SearchFileView.as_view(), name='search-file'),  # Search
    url(r'^urldownload/', views.UrlDownloadView.as_view(), name='url-download'),  # Upload from URL
    url(r'^yara/$', views.YaraRulesView.as_view(), name='yara-rules'),  # Yara

]
