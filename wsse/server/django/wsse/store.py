# wsse/server/django/wsse/store.py
# coding=utf-8
# pywsse
# Authors: Rushy Panchal, Naphat Sanguansin, Adam Libresco, Jérémie Lumbroso
# Date: August 30th, 2016
# Description: Store implementation for the Django server.

import datetime

from .models import WSSEEvent
from .... import settings

class DjangoNonceStore(object):
	'''
	Nonce store for Django ORM.
	'''
	def add_nonce(self, nonce, timestamp = None):
		'''
		Add a nonce to the store.

		:param nonce: nonce to store
		:type nonce: str

		:param timestamp: timestamp the nonce was generated at
		:type timestamp: datetime.datetime
		'''
		kwargs = {'nonce': nonce}
		if timestamp:
			kwargs['timestamp'] = timestamp

		WSSEEvent.objects.create(**kwargs)

	def has_nonce(self, nonce):
		'''
		Check if a nonce is in the store.

		:param nonce: nonce to check
		:type nonce: str
		'''
		self.clean_expired_nonces()

		return WSSEEvent.objects.filter(nonce = nonce).exists()

	def clean_expired_nonces(self):
		'''
		Clean any expired nonces from the database.
		'''
		now = datetime.datetime.utcnow().replace(microsecond = 0)
		exp_time = now - datetime.timedelta(seconds = settings.TIMESTAMP_DURATION)

		WSSEEvent.objects.filter(timestamp__lt = exp_time).delete()
