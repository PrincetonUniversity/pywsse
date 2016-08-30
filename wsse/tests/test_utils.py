# wsse/tests/test_utils.py
# py-wsse
# Author: Rushy Panchal
# Date: August 30th, 2016
# Description: Test utility functions.

from unittest import TestCase
import hashlib
import base64

from six.moves import range
import mock
import six

from wsse import utils, settings, exceptions

class TestNonce(TestCase):
	'''
	Test functions that deal with the nonce generation and usage.
	'''
	def test_genenerate_nonce_str(self):
		'''
		Generating a nonce should yield a string.
		'''
		self.assertIsInstance(utils.generate_nonce(), str)

	def test_generate_nonce_length(self):
		'''
		The length of a generated nonce should match what is specified or the
		default length.
		'''
		self.assertEqual(len(utils.generate_nonce(10)), 10)
		self.assertEqual(len(utils.generate_nonce()), settings.NONCE_LENGTH)
		self.assertEqual(len(utils.generate_nonce(settings.NONCE_LENGTH + 1)),
			settings.NONCE_LENGTH)

	def test_generate_nonce_chars(self):
		'''
		The characters in the nonce should only contain those in the specified
		string.
		'''
		allowed_chars = 'abcde'
		nonce = utils.generate_nonce(allowed_chars = allowed_chars)

		for c in nonce:
			self.assertIn(c, allowed_chars)

	def test_generate_nonce_random(self):
		'''
		Nonces generated in sequence should not clash.
		'''
		nonces = [utils.generate_nonce() for _ in range(25)]

		self.assertEqual(len(set(nonces)), len(nonces))

class TestBytes_Strings(TestCase):
	'''
	Test automatic conversion of bytes to string and vice-versa.
	'''
	def test_to_bytes(self):
		'''
		Converting a string to bytes and bytes to bytes should both return bytes.
		'''
		self.assertIsInstance(utils._to_bytes('string'), six.binary_type)
		self.assertIsInstance(utils._to_bytes(b'bytes'), six.binary_type)

	def test_from_bytes(self):
		'''
		Converting a string from bytes and bytes from bytes should both return a
		string.
		'''
		self.assertIsInstance(utils._from_bytes('string'), six.string_types)
		self.assertIsInstance(utils._from_bytes(b'bytes'), six.string_types)

class TestDigests(TestCase):
	'''
	Test hash digests.
	'''
	def test_get_digest_algorithm(self):
		'''
		Getting a digest algorithm should yield the first one from the possible
		options.
		'''
		with mock.patch.object(settings, 'ALLOWED_DIGEST_ALGORITHMS', ['SHA256']):
			self.assertEqual(utils.get_digest_algorithm(), hashlib.sha256)

		with mock.patch.object(settings, 'ALLOWED_DIGEST_ALGORITHMS',
			['ABCDEF', 'SHA256']):
			self.assertEqual(utils.get_digest_algorithm(), hashlib.sha256)

		with mock.patch.object(settings, 'ALLOWED_DIGEST_ALGORITHMS', ['MD5']):
			self.assertEqual(utils.get_digest_algorithm(), hashlib.md5)

	def test_get_digest_algorithm_none(self):
		'''
		Get the digest algorithm when no valid ones are specified.
		An error should be raised.
		'''
		with self.assertRaises(exceptions.AlgorithmNotSupported):
			with mock.patch.object(settings, 'ALLOWED_DIGEST_ALGORITHMS', ['ABCDE']):
				utils.get_digest_algorithm()

		with self.assertRaises(exceptions.AlgorithmNotSupported):
			with mock.patch.object(settings, 'ALLOWED_DIGEST_ALGORITHMS', []):
				utils.get_digest_algorithm()

	def test_b64_digest(self):
		'''
		Perform a digest using the specified algorithm of SHA1. The b64-encoded
		digest should be returned.
		'''
		with mock.patch.object(settings, 'ALLOWED_DIGEST_ALGORITHMS', ['SHA256']):
			utils_digest = utils.b64_digest('a', 'b', 'c')
			actual_digest = base64.b64encode(hashlib.sha256(b'abc').digest())

			self.assertEqual(actual_digest, utils_digest)

		with mock.patch.object(settings, 'ALLOWED_DIGEST_ALGORITHMS', ['SHA256']):
			single_digest = utils.b64_digest('abc')
			multi_digest = utils.b64_digest('a', 'b', 'c')

			self.assertEqual(single_digest, multi_digest)

	def test_b64_digest_bytes(self):
		'''
		Perform a digest of bytes using the specified algorithm of SHA1.
		The b64-encoded digest should be returned.
		'''
		with mock.patch.object(settings, 'ALLOWED_DIGEST_ALGORITHMS', ['SHA256']):
			utils_digest = utils.b64_digest(b'a', b'b', b'c')
			actual_digest = base64.b64encode(hashlib.sha256(b'abc').digest())

			self.assertEqual(actual_digest, utils_digest)

		with mock.patch.object(settings, 'ALLOWED_DIGEST_ALGORITHMS', ['SHA256']):
			single_digest = utils.b64_digest(b'abc')
			multi_digest = utils.b64_digest(b'a', b'b', b'c')

			self.assertEqual(single_digest, multi_digest)

		with mock.patch.object(settings, 'ALLOWED_DIGEST_ALGORITHMS', ['SHA256']):
			str_digest = utils.b64_digest('abc')
			bytes_digest = utils.b64_digest(b'abc')

			self.assertEqual(str_digest, bytes_digest)

	def test_b64_digest_sha1(self):
		'''
		Perform a digest using the specified algorithm of SHA1. The b64-encoded
		digest should be returned.
		'''
		with mock.patch.object(settings, 'ALLOWED_DIGEST_ALGORITHMS', ['SHA1']):
			utils_digest = utils.b64_digest('a', 'b', 'c')
			actual_digest = base64.b64encode(hashlib.sha1(b'abc').digest())

			self.assertEqual(actual_digest, utils_digest)
