# wsse/server/drf/tests/test_authentication.py
# coding=utf-8
# pywsse
# Authors: Rushy Panchal, Naphat Sanguansin, Adam Libresco, Jérémie Lumbroso
# Date: September 1st, 2016
# Description: Test DRF WSSE Authentication backend.

import contextlib
import hashlib
import base64
import datetime
import itertools

from rest_framework.test import APITestCase, APIRequestFactory
from rest_framework import status
from django.contrib.auth.models import User

from wsse import utils, settings
from wsse.compat import reverse_lazy
from wsse.server.django.wsse.models import UserSecret

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

class WSSEAuthenticationTests(APITestCase):
	'''
	Test WSSE Authentication on the API.
	'''
	factory = APIRequestFactory()
	base_url = reverse_lazy('api-test')

	@contextlib.contextmanager
	def http_auth(self, header):
		'''
		Perform HTTP authentication, through headers, in a request.
		The headers are automatically cleared afterwards.
		'''
		kwargs = {utils._django_header(settings.REQUEST_HEADER): header}
		self.client.credentials(**kwargs)
		yield

		# Clear the credential headers.
		self.client.credentials()

	@classmethod
	def setUpClass(cls):
		'''
		Set up the class for running tests.
		'''
		cls.user = User.objects.create(username = 'test')
		cls.user_secret = UserSecret.objects.create(user = cls.user)

	@classmethod
	def tearDownClass(cls):
		'''
		Tear down the class after running tests.
		'''
		cls.user.delete()

	def make_header_values(self, user = None, username = None, timestamp = None,
		digest = None, b64_digest = None, nonce = None, b64_nonce = None,
		digest_algorithm = None):
		'''
		Make the header values from the given parameters.

		:param user: (optional) user to authenticate with header
		:type user: django.contrib.auth.models.User

		:param username: (optional) username to provide in header
		:type username: str

		:param timestamp: (optional) timestamp to use in header
		:type timestamp: str

		:param digest: (optional) header digest
		:type digest: bytes

		:param b64_digest: (optional) header digest as base64
		:type b64_digest: bytes

		:param nonce: (optional) header nonce
		:type nonce: bytes

		:param b64_nonce: (optional) header nonce as base64
		:type b64_nonce: bytes

		:param digest_algorithm: (optional, default: sha256) digest algorithm to
			use. It must be supported by hashlib.
		:type digest_algorithm: str

		:return: WSSE authentication header parts
		:rtype: dict
		'''
		if user is None:
			user = self.user
		if username is None:
			username = user.username

		if timestamp is None:
			now = datetime.datetime.utcnow()
			timestamp = now.strftime(settings.TIMESTAMP_FORMATS[0])

		if nonce is None:
			nonce = utils._random_string(length = settings.NONCE_LENGTH)

		if digest is None:
			digest = utils._b64_digest(nonce, timestamp, self.user_secret.secret,
				algorithm = digest_algorithm)
		
		if b64_nonce is None:
			b64_nonce = base64.b64encode(utils._to_bytes(nonce))
		if b64_digest is not None:
			digest = b64_digest

		header_values = {
			'Username': username,
			'PasswordDigest': utils._from_bytes(digest),
			'Nonce': utils._from_bytes(b64_nonce),
			'Created': timestamp
			}

		return header_values

	def make_header(self, *args, **kwargs):
		'''
		Make the header from the given values.

		:return: WSSE authentication header
		:rtype: str
		'''
		header_values = self.make_header_values(*args, **kwargs)
		header = (', '.join('{k}="{v}"'.format(
			k = k, v = v) for k, v in header_values.items()))
		return header

	def test_valid_authentication(self):
		'''
		Authenticate with a valid username. The authentication should succeed.
		'''
		with self.http_auth(self.make_header()):
			response = self.client.get(self.base_url)

		self.assertEqual(response.status_code, status.HTTP_200_OK)

	def test_valid_authentication_alternative_timestamp_format(self):
		'''
		Authenticate with a valid username, using an alternative timestamp format.
		The authentication should succeed.
		'''
		now = datetime.datetime.utcnow()
		timestamp = now.strftime('%Y-%m-%dT%H:%M:%S.%fZ')

		with self.http_auth(self.make_header(timestamp = timestamp)):
			response = self.client.get(self.base_url)

		self.assertEqual(response.status_code, status.HTTP_200_OK)

	def test_valid_authentication_alternative_headers(self):
		'''
		Make a valid authentication request. Use various permutations of the
		header format.
		'''
		default_params = ['Username', 'PasswordDigest', 'Nonce', 'Created']

		for params in itertools.permutations(default_params):
			header_values = self.make_header_values()
			header = ('UsernameToken ' + ', '.join('{k}="{v}"'.format(
				k = param, v = header_values[param]) for param in params))
			with self.http_auth(header):
				response = self.client.get(self.base_url)

			self.assertEqual(response.status_code, status.HTTP_200_OK)

	def test_valid_authentication_drift(self):
		'''
		Authenticate with a valid username with drift on the timestamp.
		The authentication should succeed.
		'''
		ts = (datetime.datetime.utcnow() +
			datetime.timedelta(seconds = settings.DRIFT_OFFSET - 1))
		timestamp = ts.strftime('%Y-%m-%dT%H:%M:%S.%fZ')

		with self.http_auth(self.make_header()):
			response = self.client.get(self.base_url)

		self.assertEqual(response.status_code, status.HTTP_200_OK)

	def test_no_authentication(self):
		'''
		Perform a request with no attempt at authentication. Authentication
		should not succeed.
		'''
		response = self.client.get(self.base_url)
		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

	def test_wrong_format_authentication(self):
		'''
		Perform a request with incorrect authentication header format.
		Authentication should not succeed.
		'''
		with self.http_auth('WrongFormat=27'):
			response = self.client.get(self.base_url)

		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

	def test_invalid_timestamp_authentication(self):
		'''
		Perform a request with an invalid timestamp.
		Authentication should not succeed.
		'''
		with self.http_auth(self.make_header(timestamp = 'Nope')):
			response = self.client.get(self.base_url)

		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

	def test_invalid_timestamp_format_authentication(self):
		'''
		Perform a request with an invalid timestamp format.
		Authentication should not succeed.
		'''
		now = datetime.datetime.utcnow()
		timestamp = now.strftime("%m/%d/%Y, %M:%S.%f")

		with self.http_auth(self.make_header(timestamp = timestamp)):
			response = self.client.get(self.base_url)

		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

	def test_expired_timestamp(self):
		'''
		Authenticate an expired timestamp. The authentication should not succeed.
		'''
		now = datetime.datetime.utcnow() - datetime.timedelta(
			seconds = settings.TIMESTAMP_DURATION + 1)
		timestamp = now.strftime('%Y-%m-%dT%H:%M:%S.%fZ')

		with self.http_auth(self.make_header(timestamp = timestamp)):
			response = self.client.get(self.base_url)

		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

	def test_future_timestamp(self):
		'''
		Authenticate a future timestamp. The authentication should not succeed.
		'''
		now = datetime.datetime.utcnow() + datetime.timedelta(
			seconds = settings.TIMESTAMP_DURATION + 1)
		timestamp = now.strftime('%Y-%m-%dT%H:%M:%S.%fZ')

		with self.http_auth(self.make_header(timestamp = timestamp)):
			response = self.client.get(self.base_url)

		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

	def test_incorrect_username(self):
		'''
		Authenticate with an incorrect username. The authetication should not
		succeed.
		'''
		with self.http_auth(self.make_header(username = 'nope')):
			response = self.client.get(self.base_url)

		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

	def test_invalid_b64_nonce(self):
		'''
		Authenticate with a nonce that is not base64. The authentication should not
		succeed.
		'''
		with self.http_auth(self.make_header(b64_nonce = '?????????')):
			response = self.client.get(self.base_url)

		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

	def test_short_nonce(self):
		'''
		Authenticate with a nonce that is fewer than 8 characters. The
		authentication should not succeed.
		'''
		with self.http_auth(self.make_header(b64_nonce = 'short')):
			response = self.client.get(self.base_url)

		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

	def test_long_nonce(self):
		'''
		Authenticate with a nonce that is longer than 32 characters. The
		authentication should not succeed.
		'''
		with self.http_auth(self.make_header(b64_nonce = 'a' * 72)):
			response = self.client.get(self.base_url)

		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

	def test_authenticate_sha1(self):
		'''
		Authenticate with a valid header, but calculate the digest using SHA-1.
		The authentication should not succeed.
		'''
		with self.http_auth(self.make_header(
			digest_algorithm = 'sha1')):
			response = self.client.get(self.base_url)

		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

	def test_invalid_digest(self):
		'''
		Authenticate with an invalid digest. The authentication should not succeed.
		'''
		with self.http_auth(self.make_header(
			digest = 'nope'.encode('utf-8'))):
			response = self.client.get(self.base_url)

		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

	def test_invalid_digest_b64(self):
		'''
		Authenticate with an invalid digest, in base64.
		The authentication should not succeed.
		'''
		with self.http_auth(self.make_header(b64_digest = 'nope')):
			response = self.client.get(self.base_url)

		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

	def test_replay_attack(self):
		'''
		Authenticate with a valid header twice. The second authentication should
		be detected as a replay attack.
		'''
		header = self.make_header()

		with self.http_auth(header):
			response = self.client.get(self.base_url)
		with self.http_auth(header):
			second_response = self.client.get(self.base_url)

		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertEqual(second_response.status_code, status.HTTP_401_UNAUTHORIZED)

	def test_replay_attack_multiple(self):
		'''
		Authenticate with a valid header multiple times.
		The following authentication attempts should be detected as replay attacks.
		'''
		header = self.make_header()

		with self.http_auth(header):
			response = self.client.get(self.base_url)
		self.assertEqual(response.status_code, status.HTTP_200_OK)

		for _ in range(10):
			with self.http_auth(header):
				new_resp = self.client.get(self.base_url)
		
			self.assertEqual(new_resp.status_code, status.HTTP_401_UNAUTHORIZED)
