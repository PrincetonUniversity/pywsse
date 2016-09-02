# wsse/server/drf/tests/urls.py
# coding=utf-8
# pywsse
# Authors: Rushy Panchal, Naphat Sanguansin, Adam Libresco, Jérémie Lumbroso
# Date: September 1st, 2016
# Description: Test URL configuration.

from django.conf.urls import include, url

from .views import TestView

urlpatterns = [
	url(r'^$', TestView.as_view(), name = 'api-test')
	]
