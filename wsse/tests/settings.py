# wsse/tests/settings.py
# py-wsse
# Authors: Rushy Panchal, Naphat Sanguansin, Adam Libresco, Jérémie Lumbroso
# Date: September 1st, 2016
# Description: Test application settings.

DEBUG = True

DATABASES = {
	'default': {
		'ENGINE': 'django.db.backends.sqlite3',
		'NAME': ':memory:',
		}
	}

SECRET_KEY = "BITlFxZunJXWaoiKhMAE"

ROOT_URLCONF = 'wsse.tests.urls'

INSTALLED_APPS = (
	'django.contrib.auth',
	'django.contrib.contenttypes',
	'django.contrib.sessions',
	'django.contrib.sites',
	'django.contrib.staticfiles',
	'django.contrib.admin',

	'rest_framework',

	# Server-side applications
	'wsse.server.django',
	'wsse.server.drf',
	)

REST_FRAMEWORK = {
	'DEFAULT_AUTHENTICATION_CLASSES': (
			'wsse.server.drf.authentication.WSSEAuthentication',
			),
	'DEFAULT_PERMISSION_CLASSES': (
			'rest_framework.permissions.IsAuthenticated',
			),
	}
