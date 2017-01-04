# wsse/server/django/wsse/__init__.py
# coding=utf-8
# pywsse
# Authors: Rushy Panchal, Naphat Sanguansin, Adam Libresco, Jérémie Lumbroso
# Date: September 1st, 2016

from django.conf import settings
if not (hasattr(settings, 'TESTING') and settings.TESTING):
	default_app_config = 'wsse.server.django.wsse.apps.WsseConfig'
