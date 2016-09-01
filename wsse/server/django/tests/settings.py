# wsse/server/django/tests/settings.py
# py-wsse
# Author: Rushy Panchal
# Date: September 1st, 2016

DEBUG = True

DATABASES = {
		'default': {
				'ENGINE': 'django.db.backends.sqlite3',
				'NAME': 'example.sqlite',
		}
}

SECRET_KEY = "BITlFxZunJXWaoiKhMAE"

INSTALLED_APPS = (
		'django.contrib.auth',
		'django.contrib.contenttypes',
		'django.contrib.sessions',
		'django.contrib.sites',
		'django.contrib.staticfiles',
		'django.contrib.admin',

		'rest_framework',

		'wsse.server.django',
		'wsse.server.django.tests',
)
