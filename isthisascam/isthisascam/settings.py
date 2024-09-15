"""
Django settings for isthisascam project.

Generated by 'django-admin startproject' using Django 4.2.15.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.2/ref/settings/
"""
import json
from pathlib import Path
import os

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent
ISLOCAL = False
if ISLOCAL:
    with open('../config.json') as file:
        config = json.load(file)
else:
    with open('/etc/config.json') as file:
        config = json.load(file)
# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = config.get('DJANGO_SECRET_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

ALLOWED_HOSTS = ['3.135.189.181', '127.0.0.1', 'isthisascam.online','www.isthisascam.online']

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'scamapp.apps.ScamappConfig',
    'django_user_agents',
    'paypal.standard.ipn',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django_user_agents.middleware.UserAgentMiddleware',
]

ROOT_URLCONF = 'isthisascam.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
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

WSGI_APPLICATION = 'isthisascam.wsgi.application'

# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases

if DEBUG:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }
else:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': config.get('POSTGRES_DATABASE'),
            'USER': config.get('POSTGRES_USER'),
            'PASSWORD': config.get('POSTGRES_PASSWORD'),
            'HOST': 'localhost',
            'PORT': '5432',
        }
    }

# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True

# # Static files (CSS, JavaScript, Images)
if not DEBUG:
    STORAGES = {
        "default": {
            "BACKEND": "storages.backends.s3.S3Storage",
        }, "staticfiles": {
            "BACKEND": "storages.backends.s3.S3Storage",
        },

    }

AWS_ACCESS_KEY_ID = config.get('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = config.get('AWS_SECRET_ACCESS_KEY')
AWS_STORAGE_BUCKET_NAME = config.get('AWS_STORAGE_BUCKET_NAME')
AWS_S3_SIGNATURE_NAME = 's3v4',
AWS_S3_REGION_NAME = 'us-west-1'
AWS_S3_FILE_OVERWRITE = False
AWS_DEFAULT_ACL = None
AWS_S3_VERIFY = True
AWS_QUERYSTRING_AUTH = False

AWS_S3_OBJECT_PARAMETERS = {
    'CacheControl': 'max-age=86400',
}
# if DEBUG:
STATIC_URL = '/static/'

# The filesystem path to the directory you want Django to store all static files.
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

# Additional locations of static files that are not part of any app’s static files directories.
# STATICFILES_DIRS = [
#     os.path.join(BASE_DIR, 'static'),
# ]
LOGIN_URL = '/log-in'

# URL where users are redirected after logging in
# URL where users are redirected after logging out
LOGOUT_REDIRECT_URL = ''  # Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
# paypal_settings.py


PAYPAL_RECEIVER_EMAIL = config.get('PAYPAL_RECEIVER_EMAIL')
PAYPAL_TEST = True  # Set to False for live transactions
