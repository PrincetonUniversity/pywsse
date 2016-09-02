# wsse/client/requests/auth.py
# coding=utf-8
# py-wsse
# Authors: Rushy Panchal, Naphat Sanguansin, Adam Libresco, Jérémie Lumbroso
# Date: September 1st, 2016
# Description: Authentication handler for requests library.

try:
	import requests
except ImportError:
	raise ImportError('requests is required to use the requests plugin')

from ... import settings, utils

class WSSEAuth(requests.auth.AuthBase):
	'''
	Attaches HTTP Digest Authentication to the given Request object.

	Usage:
		requests.get(url, auth=WSSEAuth(username, password))

	The auth object isreusable, and can be defined separately if several
	requests will be made with the same username & password pair.

	:param username: username to include in request
	:type username: str

	:param password: password to authenticate with
	:type password: str
	'''
	def __init__(self, username, password):
		self.token_builder = utils.TokenBuilder(username, password)

	def __call__(self, r):
		'''Attach the appropriate request header to attempt WSSE authentication.'''
		r.headers[settings.REQUEST_HEADER] = self.token_builder.make_token()
		return r