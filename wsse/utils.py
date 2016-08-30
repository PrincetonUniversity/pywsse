# wsse/utils.py
# py-wsse
# Author: Rushy Panchal
# Date: August 30th, 2016
# Description: Shared utility functions for both the WSSE server and client.

import logging
import random
import string
import datetime
import hashlib
import base64

from six.moves import range
import six

from . import settings
from . import exceptions

logger = logging.getLogger(settings.LOGGER_NAME)

class TokenBuilder(object):
	'''
	A `TokenBuilder` generates tokens for the given username and password.

	:param username: username for token authentication
	:type username: str

	:param password: password for token authentication
	:type password: str
	'''
	def __init__(self, username, password):
		self.username = username
		self.password = password

	def make_token(self, nonce = None, timestamp = None):
		'''
		Make a new WSSE token with the current username and password.

		:param nonce: nonce to use in token
		:type nonce: str

		:param timestamp: timestamp the nonce was generated at
		:type timestamp: datetime.datetime

		:return: WSSE token
		:rtype: str
		'''
		if not nonce:
			nonce = generate_nonce()
		if not timestamp:
			timestamp = datetime.datetime.utcnow()

		return make_token(self.username, self.password, nonce, timestamp)

def make_token(username, password, nonce, timestamp):
	'''
	Make a WSSE token using the provided fields.

	:param username: username for token
	:type username: str

	:param password: password for token
	:type password: str

	:param nonce: nonce for token
	:type nonce: str

	:param timestamp: timestamp the token was generated at
	:type timestamp: datetime.datetime
	'''
	if timestamp < (datetime.datetime.utcnow() +
		datetime.timedelta(seconds = settings.TIMESTAMP_DURATION)):
		logger.warning('Timestamp in make_token expired: %s (%ds duration)',
			timestamp, settings.TIMESTAMP_DURATION)

	timestamp_str = timestamp.strftime(settings.TIMESTAMP_UTC_FORMAT)

	password_digest = b64_digest(nonce, timestamp_str, password)
	encoded_nonce = base64.b64encode(_to_bytes(nonce))

	fields = (
		('Username', _from_bytes(username)),
		('PasswordDigest', _from_bytes(password_digest)),
		('Nonce', _from_bytes(encoded_nonce)),
		('Created', timestamp_str),
		)

	return ', '.join('{k}={v}'.format(k = k, v = v) for k, v in fields)

def generate_nonce(length = None, allowed_chars = None):
	'''
	Generate a nonce of the given length. If the length is greater than the
	length specified in the settings, it will be truncated to the maximum
	length.

	:param length: length of nonce (defaults to settings.NONCE_LENGTH)
	:rtype length: int

	:param allowed_chars: characters to allow in nonce
	:rtype allowed_chars: str

	:return: generated nonce
	:rtype: str
	'''
	if allowed_chars is None:
		try:
			allowed_chars = string.letters
		except AttributeError:
			allowed_chars = string.ascii_letters

	if length is None or length > settings.NONCE_LENGTH:
		length = settings.NONCE_LENGTH

	nonce = ''.join(random.choice(allowed_chars) for _ in range(length))
	return nonce

def b64_digest(*args):
	'''
	Perform a digest on the arguments using the specified algorithm in the
	settings.

	:param args: arguments to digest
	:rtype args: `iter` of `str` or `bytes`
	'''
	digest_algorithm = get_digest_algorithm()
	args_str = ''.join(map(_from_bytes, args))

	return base64.b64encode(digest_algorithm(_to_bytes(args_str)).digest())

def get_digest_algorithm():
	'''
	Get the digest algorithm to use based on the settings.

	:return: digest algorithm
	:rtype: class
	'''
	possible_algorithms = filter(lambda a: a in hashlib.algorithms_available,
		(map(str.lower, settings.ALLOWED_DIGEST_ALGORITHMS)))

	for algo_name in possible_algorithms:
		if hasattr(hashlib, algo_name):
			return getattr(hashlib, algo_name)

	logger.error('No algorithm from %r found in hashlib %r',
		settings.ALLOWED_DIGEST_ALGORITHMS, hashlib.algorithms_available)
	raise exceptions.AlgorithmNotSupported('No suitable algorithm found.')

def _to_bytes(s):
	'''
	Convert a string to bytes if it is not already bytes.

	:param s: string to convert
	:type s: `str` or `bytes`

	:return: encoded string as binary data
	:rtype: bytes
	'''
	if not isinstance(s, six.binary_type):
		return s.encode('utf-8')

	return s

def _from_bytes(b):
	'''
	Convert a string from bytes if it is not already a string.

	:param b: string to convert
	:type b: `str` or `bytes`

	:return: decoded string 
	:rtype: str
	'''
	if isinstance(b, six.binary_type):
		return b.decode('utf-8')

	return b
