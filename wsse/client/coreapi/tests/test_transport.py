# wsse/client/coreapi/tests/test_transport.py
# coding=utf-8
# pywsse
# Authors: Rushy Panchal, Naphat Sanguansin, Adam Libresco, Jérémie Lumbroso
# Date: September 1st, 2016
# Description: Test the coreapi authenticated transport implementation

from django.contrib.staticfiles.testing import StaticLiveServerTestCase
from django.contrib.auth.models import User
from rest_framework import status
from coreapi import Client
from coreapi.exceptions import ErrorMessage

from wsse import settings
from wsse.compat import reverse_lazy
from wsse.server.django.wsse.models import UserSecret
from wsse.client.coreapi.transport import WSSEAuthenticatedHTTPTransport

def setUpModule():
	'''
	Set up the module for running tests.
	'''
	# Set the nonce store to the Django store after saving the current settings
	# so they can be restored later.
	global __old_nonce_settings
	__old_nonce_settings = (settings.NONCE_STORE, settings.NONCE_STORE_ARGS)

	settings.NONCE_STORE = 'wsse.server.django.wsse.store.DjangoNonceStore'
	settings.NONCE_STORE_ARGS = []

def tearDownModule():
	'''
	Tear down the module after running tests.
	'''
	# Restore the nonce settings.
	settings.NONCE_STORE, settings.NONCE_STORE_ARGS = __old_nonce_settings

class TestWSSEAuthenticatedHTTPTransport(StaticLiveServerTestCase):
	'''
	Test authenticating through the `WSSEAuthenticatedHTTPTransport` transport.
	'''
	endpoint = reverse_lazy('api-test')

	def setUp(self):
		'''
		Set up the test cases.
		'''
		self.user = User.objects.create(username = 'username')
		self.user_secret = UserSecret.objects.create(user = self.user)

		self.client = self.makeClient('username', self.user_secret.secret)
		self.base_url = '{}{}'.format(self.live_server_url, self.endpoint)

	def makeClient(self, username, password, *args, **kwargs):
		'''
		Make a coreapi client using the username/password authentication.

		:param username: username to authenticate as
		:type username: str

		:param password: password to authenticate with
		:type password: str

		:return: client that uses specified authentication
		:rtype: coreapi.Client
		'''
		wsse_transport = WSSEAuthenticatedHTTPTransport(username, password,
			*args, **kwargs)
		return Client(transports=[wsse_transport])

	def test_auth(self):
		'''
		Perform valid authentication. The user should be authenticated.
		'''
		try:
			response = self.client.get(self.base_url)
		except ErrorMessage as e:
			self.fail('Client.get failed with %s' % (str(e),))

	def test_auth_reuse(self):
		'''
		Reuse the same authentication handler. Both requests should succeed.
		'''
		try:
			response_a = self.client.get(self.base_url)
			response_b = self.client.get(self.base_url)
		except ErrorMessage as e:
			self.fail('Client.get failed with %s' % (str(e),))

	def test_auth_incorrect_password(self):
		'''
		Authneticate with an incorrect password. The authentication should fail.
		'''
		client = self.makeClient('username', '!' + self.user_secret.secret)

		with self.assertRaises(ErrorMessage) as e:
			response = client.get(self.base_url)

			self.assertEqual(e.exception.error.title, 'Unauthorized')

	def test_auth_nonexistent_username(self):
		'''
		Authneticate with a nonexistent user. The authentication should fail.
		'''
		client = self.makeClient('nonexistentuser', self.user_secret.secret)

		with self.assertRaises(ErrorMessage) as e:
			response = client.get(self.base_url)

			self.assertEqual(e.exception.error.title, 'Unauthorized')
