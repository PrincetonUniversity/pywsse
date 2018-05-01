# setup.py
# coding=utf-8
# pywsse
# Authors: Rushy Panchal, Naphat Sanguansin, Adam Libresco, Jérémie Lumbroso
# Date: August 31st, 2016
# Description: Setuptools configuration.

from setuptools import setup, find_packages

setup(
	name = 'pywsse',
	packages = find_packages(),
	version = '0.1.5',
	description = 'WSSE Authentication for various server and client backends.',
	author = 'Rushy Panchal',
	author_email = 'rushy.panchal@princeton.edu',
	url = 'https://github.com/PrincetonUniversity/pywsse',
	keywords = ['REST', 'authentication', 'wsse'],
	license = 'LGPLv3',
	classifiers = [
		'Programming Language :: Python :: 2',
		'Programming Language :: Python :: 2.7',
		'Programming Language :: Python :: 3',
		'Programming Language :: Python :: 3.4',
		'Programming Language :: Python :: 3.5',
		'Programming Language :: Python :: 3.6',
		'Topic :: Internet :: WWW/HTTP :: WSGI :: Middleware',
		'Topic :: Software Development :: Libraries :: Python Modules',
		'Intended Audience :: Developers',
		'Operating System :: OS Independent',
		'License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)',
		],
)
