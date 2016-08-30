# wsse/settings.py
# py-wsse
# Author: Rushy Panchal
# Date: August 30th, 2016
# Description: Settings for py-wsse. These settings are shared by the server
# 	and client and can be modified to alter their behavior.

# The duration for which the timestamp is valid (in seconds).
# After that duration, the timestamp will no longer allow authentication.
TIMESTAMP_DURATION = 2 * 60 * 60

# Timestamp formats. The UTC format is timezone-aware, whereas the naive format
# ignores timezones.
TIMESTAMP_UTC_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
TIMESTAMP_NAIVE_FORMAT = '%Y-%m-%dT%H:%M:%S'

# (Maximum) length of the nonce.
# :note: If using a database to store the used nonces, changing this value
# requires a database migration.
NONCE_LENGTH = 64

# Whether or not to check the nonce for validity.
SECURITY_CHECK_NONCE = True

# Whether or not to check the timestamp for validity.
SECURITY_CHECK_TIMESTAMP = True

# List of digest algorithms that are allowed. They are checked in this order.
ALLOWED_DIGEST_ALGORITHMS = ['SHA256']

# List of digest algorithms that are prohibited.
PROHIBITED_DIGEST_ALGORITHMS = ['SHA1', 'MD5']

# Root logger name.
LOGGER_NAME = 'wsse'
