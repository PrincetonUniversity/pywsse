# wsse/server/default/store.py
# coding=utf-8
# pywsse
# Authors: Rushy Panchal, Naphat Sanguansin, Adam Libresco, Jérémie Lumbroso
# Date: August 30th, 2016
# Description: Store implementation for default server.

import sqlite3
import contextlib
import datetime

from ... import settings, utc

class SQLiteNonceStore(object):
	'''
	Default store - supports adding, validating, and purging nonces.

	:param connection_url: URL to connect to
	:type connection_url: str

	:param table: name of the table to store nonces in
	:type table: str
	'''
	def __init__(self, connection_url, table = 'nonce_store'):
		self.conn_url = connection_url
		self.table_name = table
		self.db = None
		self.open()

	def open(self):
		'''
		Open the store.
		'''
		if self.db is None:
			self.db = sqlite3.connect(self.conn_url)
			self.__setup()

	def close(self):
		'''
		Close the store.
		'''
		if self.db is not None:
			self.db.commit()
			self.db.close()
			self.db = None

	@contextlib.contextmanager
	def __transaction(self):
		'''Perform a transaction on the database.'''
		cursor = self.db.cursor()
		yield cursor
		self.db.commit()

	def __setup(self):
		'''Setup the database.'''
		with self.__transaction() as cursor:
			cursor.execute('''CREATE TABLE IF NOT EXISTS
				{table} (id INTEGER PRIMARY KEY,
										 nonce VARCHAR(255) NOT NULL,
										 ts DATETIME DEFAULT CURRENT_TIMESTAMP,
										 UNIQUE(nonce))
				'''.format(table = self.table_name))
			cursor.execute('''CREATE INDEX IF NOT EXISTS idx_nonce ON
				{table}(nonce)'''.format(table = self.table_name))
			cursor.execute('''CREATE INDEX IF NOT EXISTS idx_ts ON
				{table}(ts)'''.format(table = self.table_name))

	def _clear(self):
		'''
		Clear the nonce store.
		'''
		with self.__transaction() as cursor:
			cursor.execute('DELETE FROM {table} WHERE 1=1'.format(
				table = self.table_name))

	def add_nonce(self, nonce, timestamp = None):
		'''
		Add a nonce to the store.

		:param nonce: nonce to store
		:type nonce: str

		:param timestamp: timestamp the nonce was generated at
		:type timestamp: datetime.datetime
		'''
		if not timestamp:
			timestamp = datetime.datetime.utcnow().replace(tzinfo=utc.utc)

		with self.__transaction() as cursor:
			query = 'INSERT INTO {table} (nonce, ts) VALUES (:nonce, :ts)'.format(
				table = self.table_name)
			cursor.execute(query, {'nonce': nonce, 'ts': timestamp})

	def has_nonce(self, nonce):
		'''
		Check if a nonce is in the store.

		:param nonce: nonce to check
		:type nonce: str
		'''
		self.clean_expired_nonces()

		with self.__transaction() as cursor:
			# Check if the nonce already exists.
			select_query = 'SELECT id FROM {table} WHERE nonce = :nonce'.format(
				table = self.table_name)
			cursor.execute(select_query, {'nonce': nonce})
			return bool(cursor.fetchone())

	def clean_expired_nonces(self):
		'''
		Clean any expired nonces from the database.
		'''
		now = datetime.datetime.utcnow().replace(tzinfo=utc.utc)
		exp_time = now - datetime.timedelta(seconds = settings.TIMESTAMP_DURATION)

		with self.__transaction() as cursor:
			delete_query = 'DELETE FROM {table} WHERE ts < :expired_time'.format(
				table = self.table_name)
			cursor.execute(delete_query, {'expired_time': exp_time})
