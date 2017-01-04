# wsse/server/django/wsse/models.py
# coding=utf-8
# pywsse
# Authors: Rushy Panchal, Naphat Sanguansin, Adam Libresco, Jérémie Lumbroso
# Date: September 1st, 2016
# Description: Database models for storing the nonces and user secrets.

import datetime

from django.db import models
from django.contrib.auth.models import User

from .... import settings, utils

def _generate_secret():
	'''
	Generate a new secret key.
	'''
	return utils._random_string(length = settings.SECRET_KEY_LENGTH)

class WSSEEvent(models.Model):
	'''
	The `WSSEEvent` object records an event that occured with the WSSE
	authentication. Specifically, it records when a nonce was used to prevent
	immediate re-use. 
	'''
	nonce = models.CharField(max_length = settings.NONCE_LENGTH, db_index = True)

	# We cannot use `auto_now_add = True` here because the timezone for that
	# is not explicitly known. Instead, we default to using the current time in
	# UTC, which guarantees the timezone, especially because all the timestamps
	# are stored in UTC.
	timestamp = models.DateTimeField(default = datetime.datetime.utcnow,
		db_index = True)

class UserSecret(models.Model):
	'''
	The `UserSecret` object connects every user to their secret key. The secret
	key can be deleted to prevent access without affecting the user.
	'''
	user = models.OneToOneField(User, on_delete = models.CASCADE,
		db_index = True)
	secret = models.CharField(max_length = settings.SECRET_KEY_LENGTH,
		default = _generate_secret, blank = True, null = False)
