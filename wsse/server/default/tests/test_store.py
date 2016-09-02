# wsse/server/default/tests/test_store.py
# coding=utf-8
# pywsse
# Authors: Rushy Panchal, Naphat Sanguansin, Adam Libresco, Jérémie Lumbroso
# Date: August 30th, 2016
# Description: Test default nonce store, SQLiteNonceStore.

from unittest import TestCase
import datetime

from wsse import settings
from wsse.server.default import store

class TestSQLiteNonceStore(TestCase):
	'''
	Test the `store.SQLiteNonceStore` class.
	'''
	@classmethod
	def setUpClass(cls):
		'''
		Set up the class for running tests.
		'''
		cls.store = store.SQLiteNonceStore(':memory:', 'nonce_store')
		cls.db = cls.store.db

	def tearDown(self):
		'''
		Tear down the tests after they are run.
		'''
		# Restores the database to a fresh state.
		if hasattr(self.store, '_clear'):
			self.store._clear()

	def count_nonces(self):
		'''
		Count the number of nonces in the database.

		:return: number of nonces in the database
		:rtype: int
		'''
		return self.db_query('SELECT COUNT(*) FROM nonce_store WHERE 1=1')[0]

	def get_nonces(self):
		'''
		Get all nonces from the database.

		:return: nonces in the database
		:rtype: list
		'''
		result = self.db_query('SELECT nonce FROM nonce_store WHERE 1=1',
			many = True)
		return [x[0] for x in result]

	def add_nonce(self, nonce, ts):
		'''
		Add a nonce into the database.

		:param nonce: nonce to add
		:type nonce: str

		:param ts: timestamp of the nonce
		:type ts: datetime.datetime
		'''
		self.db_query('INSERT INTO nonce_store (nonce, ts) VALUES (:nonce, :ts)',
			{'nonce': nonce, 'ts': ts})

	def db_query(self, query, *args, **kwargs):
		'''
		Get the result of a database query.

		:param query: query to run
		:type query: str

		:param *args: arguments to provide to `sqlite3.Cursor.execute`
		:type args: list
		'''
		cursor = self.db.cursor()
		cursor.execute(query, *args)
		self.db.commit()

		many = kwargs.get('many')

		if many:
			return cursor.fetchall()

		return cursor.fetchone()

	def test_add_nonce(self):
		'''
		Once a nonce is added to the store, it should be present in the database.
		'''
		self.store.add_nonce('abc')

		count = self.count_nonces()
		nonce = self.get_nonces()[0]
		
		self.assertEqual(count, 1)
		self.assertEqual(nonce, 'abc')

	def test_add_nonce_multiple(self):
		'''
		Add multiple nonces into the store. Both should be present.
		'''
		self.store.add_nonce('abc')
		self.store.add_nonce('def')

		count = self.count_nonces()
		nonce_values = self.get_nonces()
		
		self.assertEqual(count, 2)
		self.assertEqual(nonce_values, ['abc', 'def'])

	def test_has_nonce(self):
		'''
		Add a nonce to the database. Checking if it's there should be successful.
		'''
		now = datetime.datetime.utcnow()
		self.add_nonce('abc', now)

		self.assertTrue(self.store.has_nonce('abc'))
		self.assertFalse(self.store.has_nonce('def'))

	def tear_clear(self):
		'''
		Clear the store. No entries should remain.
		'''
		now = datetime.datetime.utcnow()
		self.add_nonce('abc', now)
		self.add_nonce('def', now)

		start_count = self.count_nonces()
		start_nonces = self.get_nonces()

		self.store._clear()

		end_count = self.count_nonces()
		end_nonces = self.get_nonces()

		self.assertEqual(start_count, 2)
		self.assertEqual(start_nonces, ['abc', 'def'])
		self.assertEqual(end_count, 0)
		self.assertEqual(end_nonces, [])

	def test_clean_expired_nonces(self):
		'''
		Add a nonce that is already expired. When cleaned, it should no longer
		exist.
		'''
		now = datetime.datetime.utcnow()
		self.add_nonce('abc',
			now - datetime.timedelta(seconds = settings.TIMESTAMP_DURATION + 1))
		self.add_nonce('def', now)

		start_count = self.count_nonces()
		start_nonces = self.get_nonces()

		self.store.clean_expired_nonces()

		end_count = self.count_nonces()
		end_nonces = self.get_nonces()

		self.assertEqual(start_count, 2)
		self.assertEqual(start_nonces, ['abc', 'def'])
		self.assertEqual(end_count, 1)
		self.assertEqual(end_nonces, ['def'])
