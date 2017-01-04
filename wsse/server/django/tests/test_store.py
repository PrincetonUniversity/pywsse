# wsse/server/django/tests/test_store.py
# coding=utf-8
# pywsse
# Authors: Rushy Panchal, Naphat Sanguansin, Adam Libresco, Jérémie Lumbroso
# Date: September 1st, 2016
# Description: Test the Django database store.

from django.test import TransactionTestCase

from wsse.server.default.tests import test_store
from wsse.server.django.wsse import store
from wsse.server.django.wsse.models import WSSEEvent

class TestDjangoNonceStore(TransactionTestCase,
	test_store.TestSQLiteNonceStore):
	'''
	Test the `store.DjangoNonceStore` class.
	'''
	@classmethod
	def setUpClass(cls):
		'''
		Set up the class for running tests.
		'''
		cls.store = store.DjangoNonceStore()

	def count_nonces(self):
		'''
		Count the number of nonces in the database.

		:return: number of nonces in the database
		:rtype: int
		'''
		return WSSEEvent.objects.count()

	def get_nonces(self):
		'''
		Get all nonces from the database.

		:return: nonces in the database
		:rtype: list
		'''
		return list(WSSEEvent.objects.all().values_list('nonce', flat = True))

	def add_nonce(self, nonce, ts):
		'''
		Add a nonce into the database.

		:param nonce: nonce to add
		:type nonce: str

		:param ts: timestamp of the nonce
		:type ts: datetime.datetime
		'''
		WSSEEvent.objects.create(nonce = nonce, timestamp = ts)
