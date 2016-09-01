# wsse/tests/urls.py
# py-wsse
# Authors: Rushy Panchal, Naphat Sanguansin, Adam Libresco, Jérémie Lumbroso
# Date: September 1st, 2016
# Description: Test URL configuration.

from django.conf.urls import include, url

urlpatterns = [
	url(r'^', include('wsse.server.django.tests.urls')),
	url(r'^api/', include('wsse.server.drf.tests.urls')),
	]
