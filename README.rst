pywsse
-------

.. image:: https://circleci.com/gh/PrincetonUniversity/pywsse.svg?style=svg
    :target: https://circleci.com/gh/PrincetonUniversity/pywsse

.. image:: https://badge.fury.io/py/pywsse.svg
    :target: https://badge.fury.io/py/pywsse

Authors: Rushy Panchal, Naphat Sanguansin, Adam Libresco, Jérémie Lumbroso.

Introduction
============
**pywsse** is an all-encompassing package to meet various needs for WSSE
usage - both as an authentication backend (for various frameworks) and as a
plug-and-play authentication mechanism for clients.

The motivation for this package came after dealing with various ambiguities
in the WSSE protocol - some servers require specific digest algorithms and
base64-encode different parts of the token. By utilizing a single library, you
can be assured that there the token is generated and verified in the same way
by both client and server.

Frameworks/Package Support
==========================

The following backend frameworks are currently supported:

* `Django REST Framework`_

In addition, the following client packages are supported:

* `requests`_
* `coreapi`_

Django REST Framework
^^^^^^^^^^^^^^^^^^^^^

To utilize the Django REST Framework plugin, install the *Django* plugin to
:code:`settings.INSTALLED_APPS`:

.. code:: python

  INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
    'django.contrib.staticfiles',
    'django.contrib.admin',

    'rest_framework',

    'wsse.server.django',
    )

In addition, add the authentication backend
(:code:`wsse.server.drf.authentication.WSSEAuthentication`)
to :code:`settings.REST_FRAMEWORK['DEFAULT_AUTHENTICATION_CLASSES']`:

.. code:: python

  REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
      'rest_framework.authentication.SessionAuthentication',
      'wsse.server.drf.authentication.WSSEAuthentication'
      ),
    }

Alternatively, you can set it for a subset of your views.

Please refer to the `Django REST Framework: Authentication Documentation <http://www.django-rest-framework.org/api-guide/authentication/#setting-the-authentication-scheme>`_ for more information.

Finally, set the :code:`NONCE_STORE` and :code:`NONCE_STORE_ARGS` settings
for the **pywsse** package:

.. code:: python

  import wsse
  wsse.settings.NONCE_STORE = 'wsse.server.django.store.DjangoNonceStore'
  wsse.settings.NONCE_STORE_ARGS = []

:note: Make sure to run the migrations after setting the nonce store.
  Particularly, you must run the migrations for the :code:`wsse` app:

  .. code:: bash

    $ python manage.py makemigrations wsse
    $ python manage.py migrate wsse

:note: We are looking for a way to make those migrations automatically
  detected, so that users do not have to run :code:`makemigrations wsse` -
  a pull request with this feature would be greatly appreciated!

requests
^^^^^^^^

The **requests** plugin is an authentication class that will automatically
attach the appropriate header to the request.

To do so, import the :code:`wsse.client.requests.auth.WSSEAuth` class and
attach it to the request:

.. code:: python

  import requests
  from wsse.client.requests.auth import WSSEAuth

  response = requests.get('http://localhost:8000/api/',
    auth = WSSEAuth('username', 'password'))

The :code:`WSSEAuth` class can be reused as it will generate a new token for
each request:

.. code:: python

  import requests
  from wsse.client.requests.auth import WSSEAuth

  auth = WSSEAuth('username', 'password')

  response = requests.get('http://localhost:8000/api/1/', auth = auth)
  next_response = requests.get('http://localhost:8000/api/2/', auth = auth)

coreapi
^^^^^^^

The **coreapi** plugin is just a pluggable transport that automatically
attaches the appropriate header before sending the request.

To make use of this transport, import the
:code:`wsse.client.coreapi.transport.WSSEAuthenticatedHTTPTransport` class
and add it to your list of transports to :code:`coreapi.Client`:

.. code:: python

  import coreapi
  from wsse.client.coreapi.transport import WSSEAuthenticatedHTTPTransport

  wsse_transport = WSSEAuthenticatedHTTPTransport('username', 'password')
  client = coreapi.Client(transports = [wsse_transport])

  schema = client.get('http://api.example.com')

You can also pass in any of the arguments or keyword arguments to
`coreapi.transports.HTTPTransport` *after* the username and password.

Development
===========

To run the development version of wsse, clone the repository and install the
testing requirements in :code:`requirements.txt`. Then, run the test suite
using either :code:`tox` or :code:`detox`:

.. code:: bash

  $ git clone git@github.com:PrincetonUniversity/pywsse.git
  $ cd pywsse
  $ virtualenv env
  $ source env/bin/activate
  $ pip install -r requirements.txt
  $ detox

.. note::

  :code:`detox` is a parallel version of :code:`tox`. It only runs with Python
  2.6-2.7 (but it can and will run tests for Python 3.x versions).

