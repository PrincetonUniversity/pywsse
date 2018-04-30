# wsse/utils.py
# coding=utf-8
# pywsse
# Authors: Rushy Panchal
# Date: March 30th, 2018
# Description: Compatability utilities.

try:
  from django.core.urlresolvers import reverse_lazy
except ImportError:
  from django.urls import reverse_lazy
