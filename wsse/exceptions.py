# wsse/exceptions.py
# coding=utf-8
# pywsse
# Authors: Rushy Panchal, Naphat Sanguansin, Adam Libresco, Jérémie Lumbroso
# Date: August 30th, 2016
# Description: Exceptions for pywsse.

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

class AlgorithmProhibited(WSSEException):
	'''
	Raised when an algorithm is prohibited.
	'''
	pass

class InvalidToken(WSSEException):
	'''
	Raised when a token is invalid.
	'''
	pass

class InvalidNonce(WSSEException):
	'''
	Raised when a nonce is invalid.
	'''
	pass

class InvalidTimestamp(WSSEException):
	'''
	Raised when a timestamp is invalid.
	'''
	pass

class UserException(WSSEException):
	'''
	Raised when a user-related error occurs.
	'''
	pass
