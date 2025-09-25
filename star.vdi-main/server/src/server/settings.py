# -*- coding: utf-8 -*-
'''
Settings file for vdi server (Django)
'''
import os
import django

# calculated paths for django and the site
# used as starting points for various other paths
DJANGO_ROOT = os.path.dirname(os.path.realpath(django.__file__))
BASE_DIR = '/'.join(
    os.path.dirname(os.path.abspath(__file__)).split('/')[:-1]
)  # If used 'relpath' instead of abspath, returns path of "enterprise" instead of "openvdi"

DEBUG = os.getenv('DEBUG', False)

# USE_X_FORWARDED_HOST = True
SECURE_PROXY_SSL_HEADER = (
    'HTTP_X_FORWARDED_PROTO',
    'https',
)  # For testing behind a reverse proxy

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',  # Add 'postgresql_psycopg2', 'postgresql', 'mysql', 'sqlite3' or 'oracle'.
        'OPTIONS': {
            # 'init_command': 'SET default_storage_engine=INNODB; SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED;',
            # 'init_command': 'SET storage_engine=INNODB, SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED',
            # 'init_command': 'SET storage_engine=MYISAM, SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED',
            # 'isolation_level': 'read committed',
        },
        'NAME': 'vdi',  # Or path to database file if using sqlite3.
        'USER': 'postgres',  # Not used with sqlite3.
        'PASSWORD': 'horizon',  # Not used with sqlite3.
        'HOST': os.getenv('DBHOST', 'localhost'),  # Set to empty string for localhost. Not used with sqlite3.
        'PORT': os.getenv('DBPORT', '5432'),  # Set to empty string for default. Not used with sqlite3.
        # 'CONN_MAX_AGE': 600,		     # Enable DB Pooling, 10 minutes max connection duration
    }
}
ALLOWED_HOSTS = ['*']

DEFAULT_AUTO_FIELD = 'django.db.models.AutoField'
# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# On Unix systems, a value of None will cause Django to use the same
# timezone as the operating system.
# If running in a Windows environment this must be set to the same as your
# system time zone.

# TIME_SECTION_START
TIME_ZONE = 'Europe/Moscow'
# TIME_SECTION_END

# Language code for this installation. All choices can be found here:
# http://www.i18nguy.com/unicode/language-identifiers.html
LANGUAGE_CODE = 'ru'

gettext = lambda s: s

LANGUAGES = (
    ('en', gettext('English')),
    ('ru', gettext('Russian')),
)

LANGUAGE_COOKIE_NAME = 'vdi_lang'

# If you set this to False, Django will make some optimizations so as not
# to load the internationalization machinery.
USE_I18N = True

# If you set this to False, Django will not format dates, numbers and
# calendars according to the current locale
USE_L10N = True

# Absolute filesystem path to the directory that will hold user-uploaded files.
# Example: "/home/media/media.lawrence.com/media/"
MEDIA_ROOT = ''

# URL that handles the media served from MEDIA_ROOT. Make sure to use a
# trailing slash.
# Examples: "http://media.lawrence.com/media/", "http://example.com/media/"
MEDIA_URL = ''

# Absolute path to the directory static files should be collected to.
# Don't put anything in this directory yourself; store your static files
# in apps' "static/" subdirectories and in STATICFILES_DIRS.
# Example: "/home/media/media.lawrence.com/static/"
STATIC_ROOT = os.path.join(BASE_DIR, 'static')

# URL prefix for static files.
# Example: "http://media.lawrence.com/static/"
STATIC_URL = '/vdi/res/'

# URL prefix for admin static files -- CSS, JavaScript and images.
# Make sure to use a trailing slash.
# Examples: "http://foo.com/static/admin/", "/static/admin/".
# ADMIN_MEDIA_PREFIX = '/static/admin/'

# Additional locations of static files
STATICFILES_DIRS = (
    # Put strings here, like "/home/html/static" or "C:/www/django/static".
    # Always use forward slashes, even on Windows.
    # Don't forget to use absolute paths, not relative paths.
)

# List of finder classes that know how to find static files in
# various locations.
STATICFILES_FINDERS = (
    'django.contrib.staticfiles.finders.FileSystemFinder',
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
    # 'django.contrib.staticfiles.finders.DefaultStorageFinder',
)

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.db.DatabaseCache',
        'LOCATION': 'vdi_response_cache',
        'OPTIONS': {
            'MAX_ENTRIES': 5000,
            'CULL_FREQUENCY': 3,  #  0 = Entire cache will be erased once MAX_ENTRIES is reached, this is faster on DB. if other value, will remove 1/this number items fromm cache
        },
    },
    'memory': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
    }
    # 'memory': {
    #     'BACKEND': 'django.core.cache.backends.memcached.PyLibMCCache',
    #     'LOCATION': '127.0.0.1:11211',
    # },
}

# Related to file uploading
FILE_UPLOAD_PERMISSIONS = 0o640
FILE_UPLOAD_DIRECTORY_PERMISSIONS = 0o750
FILE_UPLOAD_MAX_MEMORY_SIZE = 512 * 1024  # 512 Kb

# Make this unique, and don't share it with anybody.
SECRET_KEY = 's5ky!7b5f#s35!e38xv%e-+iey6yi-#630x)kk3kk5_j8rie2*'
# This is a very long string, an RSA KEY (this can be changed, but if u loose it, all encription will be lost)
RSA_KEY = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA3Yc+V9C+kNYZHTiM1eGeHmyz1LUBzQiuH4eru5MVbtzDeJ3y\nnOV0qYas5wc6qXiMGy2bSH+nmfSyYjjEfnBumt8BK19vbaYzPppbrJGmRfWK550Q\nB6lNuYLYIIzWCZrxuVuPzbMBfau5SpuuHshdTlUwXmwQMbSYhRx+Y4UZjM/NnMPq\ng3JCQMUBmLiM0xHmmWpAfwuWZ+9AyOL0Xwjuhr+no/1dkAYAbvhXricn5u9lzo0z\nqv3ORUCpKFCyCsZmSAxTp4q8VU/t9LIIhV9CKSZbB5J0xPFHuPZLIciar5KAO8h+\np0aEme7F59BcAmdqYopHgfdpad4D0M5XbTLiGQIDAQABAoIBAEgtbYGdMMnuCAa+\nSxzQwvz0u+78/tY4EsuRH8Ig3SXe5g1hoQ+/rzAhAirP7ywSa8vbIzIO7aO613gr\nONJdfZwWNsJT+PFH6oBmOKJUXlGC/DwUr4lff0SHPjX0zTQZ+NJE4+jIfx7cGaYW\nbTf4XnZMSVMqcGhRiDQuoXt5fWakHtZL/pBrjuKJvkhLgflD0apdDYf5WyUFapZF\n/HJnM4b1m2mioxCZ+RdQ2nKE9pAyV5wiucm4DBZlqWFiRYLvlP2KbeO2rFl9PXoG\nwwbNV+0VjA6wuBWHnaVhRjSKoOwIoxJ+nXzsVP8L1F9R7ki+3LGTk+L0KitudY55\ngwgKm1UCgYEA+5aUAS1a6oSWm8vt2IeOQJlCKexK4zeZzNL8Os87VElRpqiLbQ8G\nCprnSMLjA8iWp/annfD4dzqFEtWoOvkvn050P5ctfvBCjfyQPXLBqqnwKSQJvO47\nMaC5ydPB5/j/uhByNC9OhrF/Wz0OfgAfyK+QO+NzzrObQeA5Mc6pmD8CgYEA4Wm4\nrtx5TP3ou2aNdiWhtJ/8EObz1NZWiWN2HbNj+w+O8evSqGxqFABIVIW6E0vPU5qC\nZrZwKfI35zxZzo/CcR7i+uvgBsh7RBd+AvhtYzItUkSinfCKADcDT5CaT/z9XdcC\ntEO/PLOXDA95CgMhGAlp7sR1XzpGiMPpNRcjL6cCgYB/IsK8LY1KAaKSLGWPDEFo\nh4oV4WCendRM2zm3Bk328+4dCAMdI4BsD4ddD47ktJLdYhmmCMWmip4AvJN86buV\nB3JbSCwnf4ZCdiT1yG3xrlq8j4eUP9cN5yi7wxS0AvJHtlPf5yAJlNzE4H/YUHu/\nUGjUusYk6EJG8eY1MzgkxQKBgD5Z0AwOUD9LvKSZqWeU4TXlSwQh3jBxWV6HdJSi\nmnVHyHKCmLKdynnd2iQHGYFc5uxpQMjIjh4MMgp0VyMcANzpfj+KH13A9tfO57xK\nm3dk2cR318N4VbPZg8DubsDRagQbBVR3qN5RjuZ3ITPzyaOsdvDkxtKgfAI4rrlQ\nvRrhAoGBAMvjLDzwdnwpMMPWCUyOnlJG7sf3n67gVZd5IODIuUVxAqvvep3Qcu7w\nG5R4NuCpEK7RdlGYof/qsQSQSHkuHDdtetiAjGwI8AhBeQgZoQe3bhGlj+ReIIAm\nARRi5RORsDZ5+RSEbGxqs//WbOhvvqgPHEGncSyK4UNeK7LpWA/0\n-----END RSA PRIVATE KEY-----'

# Trusted cyphers
SECURE_CIPHERS = (
    'TLS_AES_256_GCM_SHA384'
    ':TLS_CHACHA20_POLY1305_SHA256'
    ':TLS_AES_128_GCM_SHA256'
    ':ECDHE-RSA-AES256-GCM-SHA384'
    ':ECDHE-RSA-AES128-GCM-SHA256'
    ':ECDHE-RSA-CHACHA20-POLY1305'
    ':ECDHE-ECDSA-AES128-GCM-SHA256'
    ':ECDHE-ECDSA-AES256-GCM-SHA384'
    ':ECDHE-ECDSA-AES128-SHA256'
    ':ECDHE-ECDSA-CHACHA20-POLY1305'
)
# Min TLS version
SECURE_MIN_TLS_VERSION = '1.2'


TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            os.path.join(BASE_DIR, 'templates'),
        ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.contrib.auth.context_processors.auth',
                'django.template.context_processors.debug',
                'django.template.context_processors.i18n',
                'django.template.context_processors.media',
                'django.template.context_processors.static',
                'django.template.context_processors.tz',
                'django.contrib.messages.context_processors.messages',
                'django.template.context_processors.request',
            ],
            'debug': DEBUG,
        },
    },
]

MIDDLEWARE = [
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.locale.LocaleMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'vdi.core.util.middleware.security.VDISecurityMiddleware',
    'vdi.core.util.middleware.request.GlobalRequestMiddleware',
    'vdi.core.util.middleware.xua.XUACompatibleMiddleware',
    'vdi.core.util.middleware.redirect.RedirectMiddleware',
]

SESSION_EXPIRE_AT_BROWSER_CLOSE = True
# SESSION_COOKIE_AGE = 3600
SESSION_COOKIE_HTTPONLY = False
SESSION_SERIALIZER = 'django.contrib.sessions.serializers.PickleSerializer'
SESSION_COOKIE_SAMESITE = 'Lax'

ROOT_URLCONF = 'server.urls'

# Python dotted path to the WSGI application used by Django's runserver.
WSGI_APPLICATION = 'server.wsgi.application'

INSTALLED_APPS = (
    # 'django.contrib.contenttypes', # Not used
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'vdi.VDIAppConfig',
)

# See http://docs.djangoproject.com/en/dev/topics/logging for
# more details on how to customize your logging configuration.
LOGDIR = '/svdi/server/log'
LOGFILE = 'vdi.log'
SERVICESFILE = 'services.log'
WORKERSFILE = 'workers.log'
AUTHFILE = 'auth.log'
USEFILE = 'use.log'
TRACEFILE = 'trace.log'
LOGLEVEL = DEBUG and 'DEBUG' or 'INFO'
ROTATINGSIZE = 32 * 1024 * 1024  # 32 Megabytes before rotating files

# Tests runner is default tests runner
TEST_RUNNER = 'django.test.runner.DiscoverRunner'

LOGGING = {
    'version': 1,
    'disable_existing_loggers': True,
    'filters': {
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse',
        }
    },
    'formatters': {
        'verbose': {
            'format': '%(levelname)s %(asctime)s %(module)s %(process)d %(thread)d %(message)s'
        },
        'simple': {
            'format': '%(levelname)s %(asctime)s %(module)s %(funcName)s %(lineno)d %(message)s'
        },
        'database': {'format': '%(levelname)s %(asctime)s Database %(message)s'},
        'auth': {'format': '%(asctime)s %(message)s'},
        'use': {'format': '%(asctime)s %(message)s'},
        'trace': {'format': '%(levelname)s %(asctime)s %(message)s'},
    },
    'handlers': {
        'null': {
            'level': 'DEBUG',
            'class': 'logging.NullHandler',
        },
        'file': {
            'level': 'DEBUG',
            'class': 'logging.handlers.RotatingFileHandler',
            'formatter': 'simple',
            'filename': LOGDIR + '/' + LOGFILE,
            'mode': 'a',
            'maxBytes': ROTATINGSIZE,
            'backupCount': 3,
            'encoding': 'utf-8',
        },
        'database': {
            'level': 'DEBUG',
            'class': 'logging.handlers.RotatingFileHandler',
            'formatter': 'simple',
            'filename': LOGDIR + '/' + 'sql.log',
            'mode': 'a',
            'maxBytes': ROTATINGSIZE,
            'backupCount': 3,
            'encoding': 'utf-8',
        },
        'servicesFile': {
            'level': 'DEBUG',
            'class': 'logging.handlers.RotatingFileHandler',
            'formatter': 'simple',
            'filename': LOGDIR + '/' + SERVICESFILE,
            'mode': 'a',
            'maxBytes': ROTATINGSIZE,
            'backupCount': 3,
            'encoding': 'utf-8',
        },
        'workersFile': {
            'level': 'DEBUG',
            'class': 'logging.handlers.RotatingFileHandler',
            'formatter': 'simple',
            'filename': LOGDIR + '/' + WORKERSFILE,
            'mode': 'a',
            'maxBytes': ROTATINGSIZE,
            'backupCount': 3,
            'encoding': 'utf-8',
        },
        'authFile': {
            'level': 'DEBUG',
            'class': 'logging.handlers.RotatingFileHandler',
            'formatter': 'auth',
            'filename': LOGDIR + '/' + AUTHFILE,
            'mode': 'a',
            'maxBytes': ROTATINGSIZE,
            'backupCount': 3,
            'encoding': 'utf-8',
        },
        'useFile': {
            'level': 'DEBUG',
            'class': 'logging.handlers.RotatingFileHandler',
            'formatter': 'use',
            'filename': LOGDIR + '/' + USEFILE,
            'mode': 'a',
            'maxBytes': ROTATINGSIZE,
            'backupCount': 3,
            'encoding': 'utf-8',
        },
        'traceFile': {
            'level': 'DEBUG',
            'class': 'logging.handlers.RotatingFileHandler',
            'formatter': 'trace',
            'filename': LOGDIR + '/' + TRACEFILE,
            'mode': 'a',
            'maxBytes': ROTATINGSIZE,
            'backupCount': 3,
            'encoding': 'utf-8',
        },
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
        'mail_admins': {
            'level': 'ERROR',
            'class': 'django.utils.log.AdminEmailHandler',
            'filters': ['require_debug_false'],
        },
    },
    'loggers': {
        '': {
            'handlers': ['file'],
            'level': LOGLEVEL,
        },
        'django': {
            'handlers': ['null'],
            'propagate': True,
            'level': 'INFO',
        },
        'django.request': {
            'handlers': ['file'],
            'level': 'ERROR',
            'propagate': False,
        },
        'django.db.backends': {
            'handlers': ['database'],
            'level': 'DEBUG',
            'propagate': False,
        },
        # Disable fonttools (used by reports) logging (too verbose)
        'fontTools': {
            'handlers': ['null'],
            'propagate': True,
            'level': 'ERROR',
        },
        'vdi': {
            'handlers': ['file'],
            'level': LOGLEVEL,
            'propagate': False,
        },
        'vdi.core.workers': {
            'handlers': ['workersFile'],
            'level': LOGLEVEL,
            'propagate': False,
        },
        'vdi.core.jobs': {
            'handlers': ['workersFile'],
            'level': LOGLEVEL,
            'propagate': False,
        },
        'vdi.services': {
            'handlers': ['servicesFile'],
            'level': LOGLEVEL,
            'propagate': False,
        },
        # Custom Auth log
        'authLog': {
            'handlers': ['authFile'],
            'level': 'INFO',
            'propagate': False,
        },
        # Custom Services use log
        'useLog': {
            'handlers': ['useFile'],
            'level': 'INFO',
            'propagate': False,
        },
        # Custom tracing
        'traceLog': {
            'handlers': ['traceFile'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}
