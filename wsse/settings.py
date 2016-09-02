# wsse/settings.py
# coding=utf-8
# pywsse
# Authors: Rushy Panchal, Naphat Sanguansin, Adam Libresco, Jérémie Lumbroso
# Date: August 30th, 2016
# Description: Settings for pywsse. These settings are shared by the server
# 	and client and can be modified to alter their behavior.

# The duration for which the timestamp is valid (in seconds).
# After that duration, the timestamp will no longer allow authentication.
TIMESTAMP_DURATION = 2 * 60 * 60

# Number of seconds to allow for 'drift' - offsets in the future-timestamp
# checking to allow for minor differences in time settings.
DRIFT_OFFSET = 2 * 60

# Timestamp formats. All timestamps are converted to UTC once parsed. If the
# timestamp is naive (i.e does not specify UTC or offset from UTC), it is
# assumed to be UTC.
#
# :note: The %z specifier is only supported on Python 3.2+. A custom parser is
# used when the %z specifier fails.
TIMESTAMP_FORMATS = [
	'%Y-%m-%dT%H:%M:%SZ',    # ISO 8601 in UTC (Z specifies 0 offset)
	'%Y-%m-%dT%H:%M:%S',     # ISO 8601 without timezone - assumed to be UTC
	'%Y-%m-%dT%H:%M:%S.%fZ', # ISO 8601 with microseconds in UTC
	'%Y-%m-%dT%H:%M:%S.%f',  # ISO 8601 with microseconds (assumed UTC)
	'%Y-%m-%dT%H:%M:%S%z',   # ISO 8601 with UTC offset
	'%Y-%m-%dT%H:%M:%S.%f%z' # ISO 8601 with microseconds and UTC offset
	]

# (Maximum) length of the nonce.
# :note: If using a database to store the used nonces, changing this value
# requires a database migration.
NONCE_LENGTH = 64

# Storage backend for the nonces.
NONCE_STORE = 'wsse.server.default.store.SQLiteNonceStore'
NONCE_STORE_ARGS = (':memory:',)

# Name for the request header.
REQUEST_HEADER = 'X-WSSE'

# Whether or not to check the nonce for validity.
SECURITY_CHECK_NONCE = True

# Whether or not to check the timestamp for validity.
SECURITY_CHECK_TIMESTAMP = True

# List of digest algorithms that are allowed. They are checked in this order.
ALLOWED_DIGEST_ALGORITHMS = ['SHA256']

# List of digest algorithms that are prohibited.
PROHIBITED_DIGEST_ALGORITHMS = ['SHA1', 'MD5']

# (Maximum) length of the secret key. This is only enforced when the secrets
# are stored in the database. When changed, a database migration is required.
SECRET_KEY_LENGTH = 64

# Root logger name.
LOGGER_NAME = 'wsse'
