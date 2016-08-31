# wsse/server/default/tests/test_store.py
# py-wsse
# Author: Rushy Panchal
# Date: August 30th, 2016

from unittest import TestCase
import datetime

import mock

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
		self.store._clear()

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

		count = self.db_query('SELECT COUNT(*) FROM nonce_store WHERE 1=1')
		nonce_value = self.db_query('SELECT nonce FROM nonce_store WHERE 1=1')
		
		self.assertEqual(count[0], 1)
		self.assertEqual(nonce_value[0], 'abc')

	def test_add_nonce_multiple(self):
		'''
		Add multiple nonces into the store. Both should be present.
		'''
		self.store.add_nonce('abc')
		self.store.add_nonce('def')

		count = self.db_query('SELECT COUNT(*) FROM nonce_store WHERE 1=1')
		nonce_values = self.db_query('SELECT nonce FROM nonce_store WHERE 1=1',
			many = True)
		
		self.assertEqual(count[0], 2)
		self.assertEqual(nonce_values, [('abc',), ('def',)])

	def test_has_nonce(self):
		'''
		Add a nonce to the database. Checking if it's there should be successful.
		'''
		now = datetime.datetime.utcnow()
		nonce = 'abc'

		self.db_query('INSERT INTO nonce_store (nonce, ts) VALUES (:nonce, :ts)',
			(nonce, now))

		self.assertTrue(self.store.has_nonce('abc'))
		self.assertFalse(self.store.has_nonce('def'))

	def tear_clear(self):
		'''
		Clear the store. No entries should remain.
		'''
		now = datetime.datetime.utcnow()
		self.db_query('INSERT INTO nonce_store (nonce, ts) VALUES (:nonce, :ts)',
			('abc', now))
		self.db_query('INSERT INTO nonce_store (nonce, ts) VALUES (:nonce, :ts)',
			('def', now))

		start_count = self.db_query('SELECT COUNT(*) FROM nonce_store WHERE 1=1')
		start_nonces = self.db_query('SELECT nonce FROM nonce_store WHERE 1=1',
			many = True)

		self.store._clear()

		end_count = self.db_query('SELECT COUNT(*) FROM nonce_store WHERE 1=1')
		end_nonces = self.db_query('SELECT nonce FROM nonce_store WHERE 1=1',
			many = True)

		self.assertEqual(start_count[0], 2)
		self.assertEqual(start_nonces, [('abc',), ('def',)])
		self.assertEqual(end_count[0], 0)
		self.assertEqual(end_nonces, [])

	def test_clean_expired_nonces(self):
		'''
		Add a nonce that is already expired. When cleaned, it should no longer
		exist.
		'''
		now = datetime.datetime.utcnow()
		self.db_query('INSERT INTO nonce_store (nonce, ts) VALUES (:nonce, :ts)',
			('abc', now - datetime.timedelta(
				seconds = settings.TIMESTAMP_DURATION + 1)))
		self.db_query('INSERT INTO nonce_store (nonce, ts) VALUES (:nonce, :ts)',
			('def', now))

		start_count = self.db_query('SELECT COUNT(*) FROM nonce_store WHERE 1=1')
		start_nonces = self.db_query('SELECT nonce FROM nonce_store WHERE 1=1',
			many = True)

		self.store.clean_expired_nonces()

		end_count = self.db_query('SELECT COUNT(*) FROM nonce_store WHERE 1=1')
		end_nonces = self.db_query('SELECT nonce FROM nonce_store WHERE 1=1',
			many = True)

		self.assertEqual(start_count[0], 2)
		self.assertEqual(start_nonces, [('abc',), ('def',)])
		self.assertEqual(end_count[0], 1)
		self.assertEqual(end_nonces, [('def',)])
