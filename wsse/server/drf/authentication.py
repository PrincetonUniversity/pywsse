# wsse/server/drf/authentication.py
# coding=utf-8
# pywsse
# Authors: Rushy Panchal, Naphat Sanguansin, Adam Libresco, Jérémie Lumbroso
# Date: September 1st, 2016
# Description: Django REST Framework Authentication backend.

try:
	from django.contrib.auth.models import User
	from rest_framework import authentication
	from rest_framework.exceptions import AuthenticationFailed
except ImportError:
	raise ImportError('django and rest_framework required to use DRF plugin')

from ... import utils, exceptions, settings
from ..django.wsse.models import UserSecret

class WSSEAuthentication(authentication.BaseAuthentication):
	'''
	The `WSSEAuthentication` backend provides WSSE authentication functionality
	to DRF. It can applied as an authentication backend or used on a
	per-view basis.
	'''
	def _get_password(self, username):
		'''
		Get the password for a given username.

		:param username: username to get password for
		:type username: str

		:return: password for user
		:rtype: str

		:raises KeyError: user not found
		'''
		try:
			user_secret = UserSecret.objects.get(user__username = username)
		except UserSecret.DoesNotExist:
			raise KeyError('User not found')
	
		return user_secret.secret

	def authenticate(self, request):
		'''
		Authenticate a request.

		:param request: request to authenticate
		:type request: rest_framework.request.Request

		:return: (user, auth) if authentication succeeds, None if not attempted
		:rtype: tuple

		:raises rest_framework.exceptions.AuthenticationFailed:
			if authentication fails
		'''
		header_name = utils._django_header(settings.REQUEST_HEADER)
		wsse_header = request.META.get(header_name)
		if not wsse_header:
			# If no header is provided, do not attempt authentication.
			return None

		try:
			username = utils.check_token(wsse_header, self._get_password)
		except exceptions.WSSEException as e:
			raise AuthenticationFailed(str(e))

		# There is no need to error-check getting the user because that is
		# already done in _get_password.
		if not username:
			raise AuthenticationFailed('User could not be authenticated')

		user = User.objects.get(username = username)
		return (user, None)

	def authenticate_header(self, request):
		'''
		Return the authentication header.

		:param request: incoming request
		:type request: rest_framework.request.Request
		'''
		return 'WSSE realm="", profile="UsernameToken"'
