pywsse
-------

Authors: Rushy Panchal, Naphat Sanguansin, Adam Libresco, Jérémie Lumbroso.

Introduction
============
**pywsse** is an all-encompassing package to meet various needs for WSSE
usage - both as an authentication backend (for various frameworks) and as a
plug-and-play authenticaiton mechanism for clients.

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
