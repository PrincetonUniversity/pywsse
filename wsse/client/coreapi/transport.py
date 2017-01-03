# wsse/client/coreapi/transport.py
# coding=utf-8
# pywsse
# Authors: Rushy Panchal, Naphat Sanguansin, Adam Libresco, Jérémie Lumbroso
# Date: January 3rd, 2017
# Description: WSSE-authenticated transport for CoreAPI.

try:
	from coreapi.transports import HTTPTransport
except ImportError:
	raise ImportError('coreapi is required to use the coreapi WSSE plugin')

from ... import settings, utils

class WSSEAuthenticatedHTTPTransport(HTTPTransport):
	'''
	Attaches the HTTP Digest authentication to the headers.

	Usage:

		transport = WSSEAuthenticatedHTTPTransport(username, password)
		client = coreapi.Client(transports = [transport])

	The transport can be re-used; it will automatically generate new tokens on a
	per-request basis.

	:param username: username to authenticate as
	:type username: str

	:param password: password to authenticate with
	:type password: str
	'''
	def __init__(self, username, password, *args, **kwargs):
		super(WSSEAuthenticatedHTTPTransport, self).__init__(*args, **kwargs)
		self.token_builder = utils.TokenBuilder(username, password)

	@property
	def headers(self):
		h = super(WSSEAuthenticatedHTTPTransport, self).headers
		return h.set(settings.REQUEST_HEADER, self.token_builder.make_token())
