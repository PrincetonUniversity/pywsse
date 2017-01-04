# wsse/tests/test_utils.py
# coding=utf-8
# pywsse
# Authors: Rushy Panchal, Naphat Sanguansin, Adam Libresco, Jérémie Lumbroso
# Date: August 30th, 2016
# Description: Test utility functions.

from unittest import TestCase
import hashlib
import base64
import datetime

import mock

from wsse import utils, settings, exceptions
from wsse.server.default.store import SQLiteNonceStore

class TestRandomString(TestCase):
	'''
	Test functions that deal with the random string generation.
	'''
	def test_random_string_length(self):
		'''
		The length of a generated string should match what is specified or the
		default length.
		'''
		self.assertEqual(len(utils._random_string(10)), 10)
		self.assertEqual(len(utils._random_string()), settings.NONCE_LENGTH)
		self.assertEqual(len(utils._random_string(settings.NONCE_LENGTH + 1)),
			settings.NONCE_LENGTH + 1)

	def test_random_string_chars(self):
		'''
		The characters in the string should only contain those in the specified
		list.
		'''
		allowed_chars = 'abcde'
		string = utils._random_string(allowed_chars = allowed_chars)

		for c in string:
			self.assertIn(c, allowed_chars)

	def test_random_string_is_random(self):
		'''
		Strings generated in sequence should not clash.
		'''
		strings = [utils._random_string() for _ in range(25)]

		self.assertEqual(len(set(strings)), len(strings))

class TestBytes_Strings(TestCase):
	'''
	Test automatic conversion of bytes to string and vice-versa.
	'''
	def test_to_bytes(self):
		'''
		Converting a string to bytes and bytes to bytes should both return bytes.
		'''
		self.assertIsInstance(utils._to_bytes('string'), bytes)
		self.assertIsInstance(utils._to_bytes(b'bytes'), bytes)

	def test_from_bytes(self):
		'''
		Converting a string from bytes and bytes from bytes should both return a
		string.
		'''
		self.assertIsInstance(utils._from_bytes('string'), utils.string_types)
		self.assertIsInstance(utils._from_bytes(b'bytes'), utils.string_types)

class TestDigests(TestCase):
	'''
	Test hash digests.
	'''
	def test_get_digest_algorithm(self):
		'''
		Getting a digest algorithm should yield the first one from the possible
		options.
		'''
		self.assertEqual(utils._get_digest_algorithm(), hashlib.sha256)

		self.assertEqual(utils._get_digest_algorithm(), hashlib.sha256)

		with mock.patch.object(settings, 'ALLOWED_DIGEST_ALGORITHMS',
			['ABCDEF', 'SHA256']):
			self.assertEqual(utils._get_digest_algorithm(), hashlib.sha256)

		with mock.patch.object(settings, 'ALLOWED_DIGEST_ALGORITHMS', ['MD5']):
			self.assertEqual(utils._get_digest_algorithm(), hashlib.md5)

	def test_get_digest_algorithm_none(self):
		'''
		Get the digest algorithm when no valid ones are specified.
		An error should be raised.
		'''
		with self.assertRaises(exceptions.AlgorithmNotSupported):
			with mock.patch.object(settings, 'ALLOWED_DIGEST_ALGORITHMS', ['ABCDE']):
				utils._get_digest_algorithm()

		with self.assertRaises(exceptions.AlgorithmNotSupported):
			with mock.patch.object(settings, 'ALLOWED_DIGEST_ALGORITHMS', []):
				utils._get_digest_algorithm()

	def test_get_digest_algorithm_specified(self):
		'''
		Getting a specific digest algorithm should yield that algorithm if it
		exists.
		'''
		self.assertEqual(utils._get_digest_algorithm('md5'), hashlib.md5)
		self.assertEqual(utils._get_digest_algorithm('MD5'), hashlib.md5)

		with self.assertRaises(exceptions.AlgorithmNotSupported):
				utils._get_digest_algorithm('abcdef')

	def test_b64_digest(self):
		'''
		Perform a digest using the specified algorithm of SHA1. The b64-encoded
		digest should be returned.
		'''
		utils_digest = utils._b64_digest('a', 'b', 'c')
		actual_digest = base64.b64encode(hashlib.sha256(b'abc').digest())
		self.assertEqual(actual_digest, utils_digest)

		single_digest = utils._b64_digest('abc')
		multi_digest = utils._b64_digest('a', 'b', 'c')
		self.assertEqual(single_digest, multi_digest)

	def test_b64_digest_bytes(self):
		'''
		Perform a digest of bytes using the specified algorithm of SHA1.
		The b64-encoded digest should be returned.
		'''
		utils_digest = utils._b64_digest(b'a', b'b', b'c')
		actual_digest = base64.b64encode(hashlib.sha256(b'abc').digest())
		self.assertEqual(actual_digest, utils_digest)

		single_digest = utils._b64_digest(b'abc')
		multi_digest = utils._b64_digest(b'a', b'b', b'c')
		self.assertEqual(single_digest, multi_digest)

		str_digest = utils._b64_digest('abc')
		bytes_digest = utils._b64_digest(b'abc')
		self.assertEqual(str_digest, bytes_digest)

	def test_b64_digest_sha1(self):
		'''
		Perform a digest using the specified algorithm of SHA1. The b64-encoded
		digest should be returned.
		'''
		with mock.patch.object(settings, 'ALLOWED_DIGEST_ALGORITHMS', ['SHA1']):
			utils_digest = utils._b64_digest('a', 'b', 'c')
			actual_digest = base64.b64encode(hashlib.sha1(b'abc').digest())

			self.assertEqual(actual_digest, utils_digest)

	def test_b64_digest_specified_algorithm(self):
		'''
		Perform a digest using a specified algorithm. The b64-encoded
		digest should be returned.
		'''
		utils_digest = utils._b64_digest('a', 'b', 'c', algorithm = 'sha512')
		actual_digest = base64.b64encode(hashlib.sha512(b'abc').digest())
		self.assertEqual(actual_digest, utils_digest)

class TestTimestampParser(TestCase):
	'''
	Test parsing of timestamps.
	'''
	expected_values = {
		# ISO 8601 with UTC specifier
		'2016-08-31T13:14:15Z': datetime.datetime(year = 2016, month = 8, day = 31,
				hour = 13, minute = 14, second = 15),

		# ISO 8601 without UTC specifier
		'2016-08-31T13:14:15': datetime.datetime(year = 2016, month = 8, day = 31,
				hour = 13, minute = 14, second = 15),

		# ISO 8601 with microseconds and UTC specifier
		'2015-07-21T01:23:53.123456Z': datetime.datetime(year = 2015, month = 7,
			day = 21, hour = 1, minute = 23, second = 53, microsecond = 123456),
		'2015-07-21T01:23:53.123Z': datetime.datetime(year = 2015, month = 7,
			day = 21, hour = 1, minute = 23, second = 53, microsecond = 123000),
		'2015-07-21T01:23:53.000123Z': datetime.datetime(year = 2015, month = 7,
			day = 21, hour = 1, minute = 23, second = 53, microsecond = 123),

		# ISO 8601 with microseconds without UTC specifier
		'2015-07-21T01:23:53.123456': datetime.datetime(year = 2015, month = 7,
			day = 21, hour = 1, minute = 23, second = 53, microsecond = 123456),
		'2015-07-21T01:23:53.123': datetime.datetime(year = 2015, month = 7,
			day = 21, hour = 1, minute = 23, second = 53, microsecond = 123000),
		'2015-07-21T01:23:53.000123': datetime.datetime(year = 2015, month = 7,
			day = 21, hour = 1, minute = 23, second = 53, microsecond = 123),

		# ISO 8601 with UTC offset
		'2014-06-18T07:14:54+0400': datetime.datetime(year = 2014, month = 6,
			day = 18, hour = 11, minute = 14, second = 54),
		'2014-06-18T07:14:54+0015': datetime.datetime(year = 2014, month = 6,
			day = 18, hour = 7, minute = 29, second = 54),
		'2014-06-18T07:14:54+0415': datetime.datetime(year = 2014, month = 6,
			day = 18, hour = 11, minute = 29, second = 54),
		'2014-06-18T07:14:54-0300': datetime.datetime(year = 2014, month = 6,
			day = 18, hour = 4, minute = 14, second = 54),
		'2014-06-18T07:14:54-0045': datetime.datetime(year = 2014, month = 6,
			day = 18, hour = 6, minute = 29, second = 54),
		'2014-06-18T07:14:54-0345': datetime.datetime(year = 2014, month = 6,
			day = 18, hour = 3, minute = 29, second = 54),

		# ISO 8601 with microseconds UTC offset
		'2014-06-18T07:14:54.123+0415': datetime.datetime(year = 2014, month = 6,
			day = 18, hour = 11, minute = 29, second = 54, microsecond = 123000),
		'2014-06-18T07:14:54.456-0345': datetime.datetime(year = 2014, month = 6,
			day = 18, hour = 3, minute = 29, second = 54, microsecond = 456000),
		}

	invalid_timestamps = [
		'08/15/2016',
		'08/16/2016 12:13:14',
		'2016-08-31 13:14:15Z',       # Missing T separator
		'2016-08-31T13:14:15W'        # Invalid TZ specifier (can only be Z)
		'not_really_a_timestamp',
		'2016-08-31T13:14:15 UTC',
		'2016-08-31T13:14:15 EST',
		'2014-06-18T07:14:54-03',     # Missing MM (minutes) in offset
		'2014-06-18T07:14:54-034525', # Second offsets not supported
		'September 1st, 2016',
		'2014-06-33T07:14:54-03',     # June 33rd (or any 33rd) does not exist
		'2014-06-18T24:14:54',        # Hour must be less than or equal to 23
		'2014-06-18T15:60:54',        # Minute must be less than or equal to 59
		'2014-06-18T15:58:60',        # Second must be less than or equal to 59
		'Wed Aug 31 2016 16:37:47 GMT-0400 (EDT)',
		]

	def test_parse_timestamp(self):
		'''
		Parse a valid timestamp in various formats. Valid datetime objects should
		be returned.
		'''
		for timestamp, expected in self.expected_values.items():
			received = utils._parse_timestamp(timestamp)

			# On Python 3.x, the datetime parser will account for timezones. As a
			# result, the expected and received datetimes will be different because
			# one will contain timezone info. To nromalize them, we strip out the
			# timezone info (tzinfo) and account for the offset.
			if received.tzinfo:
				received = received.replace(tzinfo=None) + received.utcoffset()

			msg = '({}) {!r} != {!r}'.format(timestamp, received, expected)
			self.assertEqual(received, expected, msg)

	def test_parse_timestampinvalid(self):
		'''
		Parse invalid timestamps, including unsupported formats. Parsing should
		fail.
		'''
		for invalid_ts in self.invalid_timestamps:
			with self.assertRaises(exceptions.InvalidTimestamp):
				utils._parse_timestamp(invalid_ts)

class TestTokenBuilder(TestCase):
	'''
	Test building tokens with the builder.
	'''
	def setUp(self):
		'''
		Set up the test case.
		'''
		username = 'username'
		password = 'secr3t'

		self.builder = utils.TokenBuilder(username, password)

	def test_make_token(self):
		'''
		Generate a token with the TokenBuilder. It should match the proper
		parameters.
		'''
		nonce = 'abcdef'
		now = datetime.datetime(year = 2016, month = 9, day = 1)
		
		expected_token = ', '.join((
			'Username="username"',
			'PasswordDigest="8p5hLaL4rzZOMdOIcX6VGscduxzAY8uNflY2I415S0Q="',
			'Nonce="YWJjZGVm"',
			'Created="2016-09-01T00:00:00Z"'
			))

		self.assertEqual(expected_token, self.builder.make_token(nonce, now))

	def test_make_token_new(self):
		'''
		Generate a token with the TokenBuilder without a specified nonce
		or timestamp.
		'''
		self.assertIsInstance(self.builder.make_token(), str)

class TestTokens(TestCase):
	'''
	Test making and validating tokens.
	'''
	def tearDown(self):
		'''
		Tear down the tests after they are run.
		'''
		store = utils._get_nonce_store()
		store._clear()

	def test_get_nonce_store(self):
		'''
		Get the nonce store. It should be the default store.
		'''
		self.assertIsInstance(utils._get_nonce_store(), SQLiteNonceStore)

	def test_make_token(self):
		'''
		Make a token. It should match the proper parameters.
		'''
		username = 'username'
		password = 'secr3t'
		nonce = 'abcdef'
		now = datetime.datetime(year = 2016, month = 9, day = 1)

		expected_token = ', '.join((
			'Username="username"',
			'PasswordDigest="8p5hLaL4rzZOMdOIcX6VGscduxzAY8uNflY2I415S0Q="',
			'Nonce="YWJjZGVm"',
			'Created="2016-09-01T00:00:00Z"'
			))

		received_token = utils.make_token(username, password, nonce, now)

		self.assertEqual(expected_token, received_token)

	def test_parse_token(self):
		'''
		Parse the components of a token. The resulting dictionary should contain
		the token's parameters.
		'''
		username = 'user'
		password_digest = '8p5hLaL4rzZOMdOIcX6VGscduxzAY8uNflY2I415S0Q'
		nonce = 'YWJjZGVm'
		created = '2016-09-01T00:00:00Z'

		expected_values = (username, password_digest, nonce, created)
		token = ('Username="{}", PasswordDigest="{}", Nonce="{}", ' +
			'Created="{}"').format(*expected_values)
		
		self.assertEqual(utils._parse_token(token), expected_values)

	def test_parse_token_no_quotes(self):
		'''
		Parse the components of a token without quotes surrounding the values.
		The resulting dictionary should contain the token's parameters.
		'''
		username = 'user'
		password_digest = '8p5hLaL4rzZOMdOIcX6VGscduxzAY8uNflY2I415S0Q'
		nonce = 'YWJjZGVm'
		created = '2016-09-01T00:00:00Z'

		expected_values = (username, password_digest, nonce, created)
		token = ('Username={}, PasswordDigest={}, Nonce={}, ' +
			'Created={}').format(*expected_values)
		
		self.assertEqual(utils._parse_token(token), expected_values)

	def test_parse_token_missing_param(self):
		'''
		Parse the components of a token when missing a parameter.
		An exception should be raised.
		'''
		token = 'Username="username", Nonce="nonce"'

		with self.assertRaises(exceptions.InvalidToken):
			utils._parse_token(token)

	def test_check_token(self):
		'''
		Check a token that was just generated.
		'''
		now = datetime.datetime.utcnow()
		nonce = utils._random_string()
		token = utils.make_token('user', 'secr3t', nonce, now)

		self.assertEqual(utils.check_token(token, lambda x: 'secr3t'), 'user')

	def test_check_token_alterntive_timestamp_format(self):
		'''
		Check a token that was just generated with a timestamp in a different
		format.
		'''
		for fmt in settings.TIMESTAMP_FORMATS[1:]:
			now = datetime.datetime.utcnow()
			nonce = utils._random_string()
			token = utils.make_token('user', 'secr3t', nonce, now,
				ts_format = fmt)

			self.assertEqual(utils.check_token(token, lambda x: 'secr3t'), 'user')

	def test_check_token_invalid_timestamp_format(self):
		'''
		Check a token that has a timestamp in an invalid format.
		'''
		ts = datetime.datetime.utcnow()
		nonce = utils._random_string()
		token = utils.make_token('user', 'secr3t', nonce, ts,
			ts_format = 'prefix-{}-suffix'.format(settings.TIMESTAMP_FORMATS[0]))

		with self.assertRaises(exceptions.InvalidTimestamp):
			utils.check_token(token, lambda x: 'secr3t')

	def test_check_token_drift(self):
		'''
		Check a token that has a timestamp with drift. The user should still be
		authenticated.
		'''
		ts = (datetime.datetime.utcnow() +
			datetime.timedelta(seconds = settings.DRIFT_OFFSET - 1))
		nonce = utils._random_string()
		token = utils.make_token('user', 'secr3t', nonce, ts)

		self.assertEqual(utils.check_token(token, lambda x: 'secr3t'), 'user')

	def test_check_token_drift_excessive(self):
		'''
		Check a token that has a timestamp with excessive drift.
		An error should be raised.
		'''
		ts = (datetime.datetime.utcnow() +
			datetime.timedelta(seconds = settings.DRIFT_OFFSET + 1))
		nonce = utils._random_string()
		token = utils.make_token('user', 'secr3t', nonce, ts)

		with self.assertRaises(exceptions.InvalidTimestamp):
			utils.check_token(token, lambda x: 'secr3t')

	def test_check_token_expired_timestamp(self):
		'''
		Check a token that has an expired timestamp. An error should be raised.
		'''
		ts = (datetime.datetime.utcnow() -
			datetime.timedelta(seconds = settings.TIMESTAMP_DURATION + 1))
		nonce = utils._random_string()
		token = utils.make_token('user', 'secr3t', nonce, ts)

		with self.assertRaises(exceptions.InvalidTimestamp):
			utils.check_token(token, lambda x: 'secr3t')

	def test_check_token_future_timestamp(self):
		'''
		Check a token that has a timestamp in the future. An error should be
		raised.
		'''
		ts = (datetime.datetime.utcnow() +
			datetime.timedelta(seconds = settings.DRIFT_OFFSET + 1))
		nonce = utils._random_string()
		token = utils.make_token('user', 'secr3t', nonce, ts)

		with self.assertRaises(exceptions.InvalidTimestamp):
			utils.check_token(token, lambda x: 'secr3t')

	def test_check_token_invalid_timestamp_disabled_security(self):
		'''
		With disabled timestamp security, invalid timestamps should still
		succeed.
		'''
		now = datetime.datetime.utcnow()
		nonce = utils._random_string()
		past = now - datetime.timedelta(seconds = settings.TIMESTAMP_DURATION + 1)
		past_token = utils.make_token('user', 'secr3t', nonce, past)

		future = now + datetime.timedelta(seconds = settings.DRIFT_OFFSET + 1)
		nonce = utils._random_string()
		future_token = utils.make_token('user', 'secr3t', nonce, future)

		with mock.patch.object(settings, 'SECURITY_CHECK_TIMESTAMP', False):
			try:
				self.assertEqual(utils.check_token(past_token, lambda x: 'secr3t'),
					'user')
			except exceptions.InvalidTimestamp:
				self.fail('InvalidTimestamp raised with expired timestamp and ' +
					'timestamp security disabled.')

			try:
				self.assertEqual(utils.check_token(future_token, lambda x: 'secr3t'),
					'user')
			except exceptions.InvalidTimestamp:
				self.fail('InvalidTimestamp raised with expired timestamp and ' +
					'timestamp security disabled.')

	def test_check_token_short_nonce(self):
		'''
		Check a token with a short nonce - it should be rejected.
		'''
		now = datetime.datetime.utcnow()
		nonce = utils._random_string(length = settings.NONCE_LENGTH - 1)
		token = utils.make_token('user', 'secr3t', nonce, now)

		with self.assertRaises(exceptions.InvalidNonce):
			utils.check_token(token, lambda x: 'secr3t')

	def test_check_token_long_nonce(self):
		'''
		Check a token with a long nonce - it should be rejected.
		'''
		now = datetime.datetime.utcnow()
		nonce = utils._random_string() + 'a'
		token = utils.make_token('user', 'secr3t', nonce, now)

		with self.assertRaises(exceptions.InvalidNonce):
			utils.check_token(token, lambda x: 'secr3t')

	def test_check_token_replay_attack(self):
		'''
		Check a token twice - a replay attack should be detected.
		'''
		now = datetime.datetime.utcnow()
		nonce = utils._random_string()
		token = utils.make_token('user', 'secr3t', nonce, now)

		utils.check_token(token, lambda x: 'secr3t')
		with self.assertRaises(exceptions.InvalidNonce):
			utils.check_token(token, lambda x: 'secr3t')

	def test_check_token_replay_attack_disabled_security(self):
		'''
		Check a token twice, but with nonce security disabled. A replay attack
		should not be detected.
		'''
		now = datetime.datetime.utcnow()
		nonce = utils._random_string()
		token = utils.make_token('user', 'secr3t', nonce, now)

		with mock.patch.object(settings, 'SECURITY_CHECK_NONCE', False):
			self.assertEqual(utils.check_token(token, lambda x: 'secr3t'), 'user')

			try:
				self.assertEqual(utils.check_token(token, lambda x: 'secr3t'), 'user')
			except exceptions.InvalidNonce:
				self.fail('InvalidNonce raised with nonce security disabled.')

	def test_check_token_invalid_password(self):
		'''
		Check a valid token with an invalid password.
		'''
		now = datetime.datetime.utcnow()
		nonce = utils._random_string()
		token = utils.make_token('user', 'wrong password', nonce, now)

		self.assertIsNone(utils.check_token(token, lambda x: 'secr3t'))

	def test_check_token_nonexistent_user(self):
		'''
		Check a valid token but with a user does not exist. An error should be
		raised.
		'''
		users = {'username': None}
		now = datetime.datetime.utcnow()
		nonce = utils._random_string()
		token = utils.make_token('user', 'secr3t', nonce, now)

		with self.assertRaises(exceptions.UserException):
			utils.check_token(token, lambda x: users[x])

	def test_check_token_alternative_algorithm(self):
		'''
		Check a valid token with an alternative algorithm.
		'''
		now = datetime.datetime.utcnow()
		nonce = utils._random_string()
		token = utils.make_token('user', 'secr3t', nonce, now,
			algorithm = 'sha512')

		with mock.patch.object(settings, 'ALLOWED_DIGEST_ALGORITHMS',
			['SHA256', 'SHA512']):
			self.assertEqual(utils.check_token(token, lambda x: 'secr3t'), 'user')

	def test_check_token_prohibited_algorithms(self):
		'''
		Check a valid token with prohibited algorithms. An error should be raised.
		'''
		for algorithm in settings.PROHIBITED_DIGEST_ALGORITHMS:
			now = datetime.datetime.utcnow()
			nonce = utils._random_string()
			token = utils.make_token('user', 'secr3t', nonce, now,
				algorithm = algorithm.lower())

			with self.assertRaises(exceptions.AlgorithmProhibited):
				utils.check_token(token, lambda x: 'secr3t')
