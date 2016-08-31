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
import re
import pydoc

from six.moves import range
import six

from . import settings
from . import exceptions

logger = logging.getLogger(settings.LOGGER_NAME)

_TOKEN_RE = re.compile(
	r'''
		(?P<key>\w+)\s*=\s* # Key consists of only alphanumerics
		(?P<quote>["']?)    # Optional quote character.
		(?P<value>.*?)      # Value is a non greedy match
		(?P=quote)          # Closing quote equals the first.
		($|,)               # Entry ends with comma or end of string
	''', re.VERBOSE)

_TS_OFFSET_RE = re.compile(
	r'''
		^
		(?P<timestamp>.+)    # Main part of timestamp
		(?P<direction>\+|\-) # Offset direction (+ or -)
		(?P<hour>\d{2})      # Hour offset (HH)
		(?P<minute>\d{2})    # Minute offset (MM)
		$
	''', re.VERBOSE)

_STORES = {}

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
			nonce = _generate_nonce()
		if not timestamp:
			timestamp = datetime.datetime.utcnow()

		return make_token(self.username, self.password, nonce, timestamp)

def make_token(username, password, nonce, timestamp, ts_format = None,
	algorithm = None):
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

	:param ts_format: format for the timestamp (optional)
	:type ts_format: str

	:param algorithm: algorithm to use for digest (optional)
	:type algorithm: str

	:return: WSSE token
	:rtype: str
	'''
	if timestamp < (datetime.datetime.utcnow() -
		datetime.timedelta(seconds = settings.TIMESTAMP_DURATION)):
		logger.warning('Timestamp in make_token expired: %s (%ds duration)',
			timestamp, settings.TIMESTAMP_DURATION)

	if not ts_format:
		ts_format = settings.TIMESTAMP_FORMATS[0]
	timestamp_str = timestamp.strftime(ts_format)

	password_digest = _b64_digest(nonce, timestamp_str, password,
		algorithm = algorithm)
	encoded_nonce = base64.b64encode(_to_bytes(nonce))

	fields = (
		('Username', _from_bytes(username)),
		('PasswordDigest', _from_bytes(password_digest)),
		('Nonce', _from_bytes(encoded_nonce)),
		('Created', timestamp_str),
		)

	return ', '.join('{k}="{v}"'.format(k = k, v = v) for k, v in fields)

def check_token(token, get_password = lambda username: username):
	'''
	Check if a token is valid.

	:param token: token to check
	:type token: str

	:param get_password: function to get password given username
	:type get_password: types.FunctionType

	:return: whether or not the token is valid
	:rtype: bool

	:raises exceptions.InvalidTimestamp: timestamp is in invalid format or
		expired/in future
	:raises exceptions.InvalidNonce: nonce is not proper length or already used
	:raises exceptions.InvalidToken: token is not in proper format
	:raises exceptions.UserException: user's password not found
	:raises exceptions.AlgorithmProhibited: digest algorithm is explicitly
		prohibited
	'''
	username, encoded_digest, encoded_nonce, created = _parse_token(token)

	nonce = base64.b64decode(encoded_nonce)
	timestamp = _parse_timestamp(created)

	if settings.SECURITY_CHECK_TIMESTAMP:
		now = datetime.datetime.utcnow()
		expired_time = now - datetime.timedelta(
			seconds = settings.TIMESTAMP_DURATION)

		if (expired_time > timestamp or timestamp > now):
			msg = 'The timestamp {} is expired or in the future.'.format(created)
			logger.info(msg)
			raise exceptions.InvalidTimestamp(msg)

	if settings.SECURITY_CHECK_NONCE:
		if len(nonce) != settings.NONCE_LENGTH:
			msg = 'Nonce should be {} in length: {}.'.format(settings.NONCE_LENGTH,
				nonce)
			logger.info(msg)
			raise exceptions.InvalidNonce(msg)

		nonce_store = _get_nonce_store()

		# Check if the nonce has already been used.
		if nonce_store.has_nonce(nonce):
			msg = 'The nonce {} has already been used.'.format(nonce)
			logger.info(msg)
			raise exceptions.InvalidNonce(msg)

		nonce_store.add_nonce(nonce)

	try:
		password = get_password(username)
	except Exception as e:
		msg = 'Password for user {} not found with error {}.'.format(
			username, e.msg)
		logger.error(msg)
		raise exceptions.UserException(msg)
	else:
		# For any of the allowed algorithms, check if the digest matches
		# the expected digest.
		for algorithm in settings.ALLOWED_DIGEST_ALGORITHMS:
			valid_digest = _to_bytes(_b64_digest(nonce, created, password,
				algorithm = algorithm.lower()))

			if valid_digest == encoded_digest:
				return True

		# Check all of the prohibited algorithms - if the received digest matches
		# that of a prohibited algorithm, then an error is raised saying that
		# the algorithm is prohibited.
		for algorithm in settings.PROHIBITED_DIGEST_ALGORITHMS:
			valid_digest = _b64_digest(nonce, created, password,
				algorithm = algorithm.lower())

			if valid_digest == encoded_digest:
				msg = 'Prohibited algorithm {} used for digest'.format(algorithm)
				logger.info(msg)
				raise exceptions.AlgorithmProhibited(msg)

	return False

### Internal Methods

def _parse_token(token):
	'''
	Parse the token to extract the parameters.

	:param token: token to parse
	:type token: str

	:return: tuple of (Username, PasswordDigest, Nonce, Created)
	:rtype: tuple

	:raises ~.exceptions.InvalidToken: invalid token
	'''
	try:
		key_values = {match.group('key'): match.group('value')
			for match in _TOKEN_RE.finditer(token)}
	except (AttributeError, StopIteration):
		key_values = {}

	missing_params = []
	for param in ('Username', 'PasswordDigest', 'Nonce', 'Created'):
		if param not in key_values:
			missing_params.append(param)

	if missing_params:
		msg = 'Token {} missing parameters: {!r}'.format(token, missing_params)
		logger.info(msg)

		raise exceptions.InvalidToken(msg)

	return (key_values['Username'], key_values['PasswordDigest'],
		key_values['Nonce'], key_values['Created'])

def _parse_timestamp(timestamp):
	'''
	Parse a timestamp. Attempts the formats specified in the settings in the
	order given.

	:param timestamp: timestamp to parse
	:rtype timestamp: str

	:return: parsed timestamp
	:rtype: datetime.datetime

	:raises exceptions.InvalidTimestamp: invalid timestamp format
	'''
	for fmt in settings.TIMESTAMP_FORMATS:
		try:
			return datetime.datetime.strptime(timestamp, fmt)
		except ValueError:
			# If the format ends with a '%z', it expects a UTC offset. However,
			# Python versions under 3.2 do not support the %z format. So, the offset
			# is parsed manually and the rest of the timestamp is passed on to the
			# original strptime parser.
			if fmt.endswith('%z'):
				match = _TS_OFFSET_RE.match(timestamp)
				if not match: continue

				try:
					# Parse the base part of the string and the offset (with direction).
					base = datetime.datetime.strptime(match.group('timestamp'), fmt[:-2])
					direction = -1 if match.group('direction') == '-' else 1
					offset = datetime.timedelta(hours = int(match.group('hour')),
						minutes = int(match.group('minute')))

					return base + (direction * offset)

				except (ValueError, IndexError):
					continue

			else: continue
		
	msg = 'Invalid timestamp {}, expected one of {!r}.'.format(timestamp,
		settings.TIMESTAMP_FORMATS)
	logger.info(msg)
	raise exceptions.InvalidTimestamp(msg)

def _generate_nonce(length = None, allowed_chars = None):
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

def _b64_digest(*args, **kwargs):
	'''
	Perform a digest on the arguments using the specified algorithm in the
	settings.

	:param args: arguments to digest
	:rtype args: `iter` of `str` or `bytes`
	'''
	algorithm = kwargs.get('algorithm')
	digest_algorithm = _get_digest_algorithm(algorithm)
	args_str = ''.join(map(_from_bytes, args))

	return base64.b64encode(digest_algorithm(_to_bytes(args_str)).digest())

def _get_digest_algorithm(name = None):
	'''
	Get the digest algorithm to use based on the settings.

	:param name: name of algorithm to use
	:type name: str

	:return: digest algorithm
	:rtype: class
	'''
	if name:
		possible_algorithms = [name.lower()]
	else:
		possible_algorithms = filter(lambda a: a in hashlib.algorithms_available,
			(map(str.lower, settings.ALLOWED_DIGEST_ALGORITHMS)))

	for algo_name in possible_algorithms:
		if hasattr(hashlib, algo_name):
			return getattr(hashlib, algo_name)

	logger.error('No algorithm from %r found in hashlib %r',
		settings.ALLOWED_DIGEST_ALGORITHMS, hashlib.algorithms_available)
	raise exceptions.AlgorithmNotSupported('No suitable algorithm found.')

def _get_nonce_store():
	'''
	Get the nonce store from the given setting.
	'''
	store_name = settings.NONCE_STORE

	if store_name in _STORES:
		return _STORES[store_name]

	store = pydoc.locate(store_name)(*settings.NONCE_STORE_PARAMS)

	_STORES[store_name] = store

	return store

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
