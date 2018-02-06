# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from django.conf.urls import include, url
from django.contrib import admin

from viper.core.config import __config__

cfg = __config__


urlpatterns = [
    url(r'^', include('viper.web.viperweb.urls')),
    url(r'^', include('favicon.urls')),
    url(r'^admin/', admin.site.urls),
    url(r'^api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    url(r'^api/', include('viper.web.viperapi.urls')),
]
