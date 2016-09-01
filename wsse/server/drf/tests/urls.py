# wsse/server/drf/tests/urls.py
# py-wsse
# Author: Rushy Panchal
# Date: September 1st, 2016
# Description: Test URL configuration.

from django.conf.urls import include, url

from .views import TestView

urlpatterns = [
	url(r'^$', TestView.as_view(), name = 'api-test')
	]
