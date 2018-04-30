# wsse/client/requests/tests/test_auth.py
# coding=utf-8
# pywsse
# Authors: Rushy Panchal, Naphat Sanguansin, Adam Libresco, Jérémie Lumbroso
# Date: September 1st, 2016
# Description: Test the requests authentication implementation

from django.contrib.staticfiles.testing import StaticLiveServerTestCase
from django.contrib.auth.models import User
from rest_framework import status
import requests

from wsse import settings
from wsse.compat import reverse_lazy
from wsse.server.django.wsse.models import UserSecret
from wsse.client.requests.auth import WSSEAuth

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

class TestWSSEAuth(StaticLiveServerTestCase):
	'''
	Test authenticating through the `WSSEAuth` handler.
	'''
	endpoint = reverse_lazy('api-test')

	def setUp(self):
		'''
		Set up the test cases.
		'''
		self.user = User.objects.create(username = 'username')
		self.user_secret = UserSecret.objects.create(user = self.user)

		self.auth = WSSEAuth('username', self.user_secret.secret)
		self.base_url = '{}{}'.format(self.live_server_url, self.endpoint)

	def test_auth(self):
		'''
		Perform valid authentication. The user should be authenticated.
		'''
		response = requests.get(self.base_url, auth = self.auth)
		self.assertEqual(response.status_code, status.HTTP_200_OK)

	def test_auth_reuse(self):
		'''
		Reuse the same authentication handler. Both requests should succeed.
		'''
		response_a = requests.get(self.base_url, auth = self.auth)
		response_b = requests.get(self.base_url, auth = self.auth)

		self.assertEqual(response_a.status_code, status.HTTP_200_OK)
		self.assertEqual(response_b.status_code, status.HTTP_200_OK)

	def test_auth_incorrect_password(self):
		'''
		Authneticate with an incorrect password. The authentication should fail.
		'''
		response = requests.get(self.base_url, auth = WSSEAuth('username',
			'!' + self.user_secret.secret))
		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

	def test_auth_nonexistent_username(self):
		'''
		Authneticate with a nonexistent user. The authentication should fail.
		'''
		response = requests.get(self.base_url, auth = WSSEAuth('nonexistentuser',
			self.user_secret.secret))
		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
