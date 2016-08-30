# wsse/__init__.py
# py-wsse
# Author: Rushy Panchal
# Date: August 30th, 2016

import logging

from . import settings

# If a handler is not already present, add a basic null handler to suppress
# errors.
logger = logging.getLogger(settings.LOGGER_NAME)

if not logger.handlers:
	logger.addHandler(logging.NullHandler())
