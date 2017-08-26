# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from django.conf.urls import include, url
from django.contrib import admin

from viper.core.config import Config

cfg = Config()


urlpatterns = [
    url(r'^', include('web.viperweb.urls')),
    url(r'^admin/', include(admin.site.urls)),
    url(r'^api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    url(r'^api/', include('web.viperapi.urls')),
]
