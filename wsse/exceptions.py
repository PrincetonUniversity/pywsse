# wsse/exceptions.py
# py-wsse
# Author: Rushy Panchal
# Date: August 30th, 2016
# Description: Exceptions for py-wsse.

class WSSEException(Exception):
	'''
	Base class for all WSSE exceptions.
	'''
	pass

class AlgorithmNotSupported(WSSEException):
	'''
	Raised when a suitable digest algorithm is not found.
	'''
	pass

class InvalidToken(WSSEException):
	'''
	Raised when a token is invalid.
	'''
	pass
