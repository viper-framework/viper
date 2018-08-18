# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
import os
import sys
import logging

from viper.core.project import __project__
from viper.core.config import __config__

log = logging.getLogger("viper-web")
cfg = __config__

# add base_path to python path
sys.path.append(__project__.base_path)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# https://github.com/cuckoosandbox/cuckoo/blob/master/cuckoo/web/web/settings.py
# Unique secret key generator. Secret key will be placed at $storage_path/.secret_key.
secret_key_path = os.path.join(__project__.base_path, ".secret_key")
if not os.path.exists(secret_key_path):
    # Using the same generation schema of Django startproject.
    from django.utils.crypto import get_random_string
    SECRET_KEY = get_random_string(50, "abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)")
    open(secret_key_path, "w").write(SECRET_KEY)
else:
    SECRET_KEY = open(secret_key_path, "r").read()


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/2.0/howto/deployment/checklist/

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

# ALLOWED_HOSTS = []
ALLOWED_HOSTS = ['*']

# Application definition

INSTALLED_APPS = (
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'whitenoise.runserver_nostatic',
    'django.contrib.staticfiles',
    'django_extensions',
    'favicon',
    'sslserver',
    'rest_framework',
    'rest_framework.authtoken',
    'bootstrapform',
    'viper.web.viperweb',
    'viper.web.viperapi',
    'rest_framework_swagger',  # has to come after viperapi so that we can override the template
)

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'viper.web.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'web'), os.path.join(BASE_DIR, 'viperweb'), os.path.join(BASE_DIR, 'viperweb/templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]


REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework.authentication.BasicAuthentication',
        'rest_framework.authentication.TokenAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ),
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.LimitOffsetPagination',
    'PAGE_SIZE': 8,
}

SWAGGER_SETTINGS = {
    'VALIDATOR_URL': None
}


FILE_UPLOAD_HANDLERS = [
    'django.core.files.uploadhandler.TemporaryFileUploadHandler'
]

FILE_UPLOAD_TEMP_DIR = "/tmp/"


WSGI_APPLICATION = 'viper.web.wsgi.application'


# Database
# https://docs.djangoproject.com/en/2.0/ref/settings/
# We keep the database around so we can do admin stuff
# In the future use viper config file to set this.

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(__project__.base_path, 'admin.db'),
    }
}


LOGGING = {
    'version': 1,
    'formatters': {
        'verbose': {
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s',
            'datefmt': "%Y-%m-%d %H:%M:%S",
        },
        'simple': {
            'format': '%(levelname)s %(message)s'
        },
    },
    'handlers': {
        'null': {
            'level': 'DEBUG',
            'class': 'logging.NullHandler',
            'formatter': 'verbose'
        },
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose'
        },
    },
    'loggers': {
        'django': {
            # 'handlers': ['null'],
            'handlers': ['console'],
            'propagate': True,
            'level': 'INFO',
        },
        'viper': {
            # 'handlers': ['null'],
            'handlers': ['console'],
            'propagate': True,
            'level': 'INFO',
        },
        'viper-web': {
            # 'handlers': ['null'],
            'handlers': ['console'],
            'propagate': True,
            'level': 'DEBUG',
        },
        'sqlalchemy.pool.NullPool': {
            'handlers': ['null'],
            'propagate': True,
            'level': 'INFO',
        },
        'werkzeug': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': True,
        },
    },
}


# Internationalization
# https://docs.djangoproject.com/en/2.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/2.0/howto/static-files/

STATIC_URL = '/static/'

STATIC_ROOT = os.path.join(__project__.base_path, "static/")

# Favicon https://pypi.python.org/pypi/django-favicon
FAVICON_PATH = STATIC_URL + 'viperweb/images/favicon.png'

# Import local settings from $storage_path/settings_local.py
try:
    from settings_local import *  # noqa
    log.debug("Found the settings_local.py file.\n")
except ImportError:
    log.debug("There is no settings_local.py file.\n")
