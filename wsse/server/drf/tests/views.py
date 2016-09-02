# wsse/server/drf/tests/views.py
# coding=utf-8
# pywsse
# Authors: Rushy Panchal, Naphat Sanguansin, Adam Libresco, Jérémie Lumbroso
# Date: September 1st, 2016
# Description: Test views.

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

class TestView(APIView):
	'''
	Test view to test authentication.
	'''
	def get(self, request, format = None):
		'''
		GET request.
		'''
		return Response('', status = status.HTTP_200_OK)

	def put(self, request, format = None):
		'''
		PUT request.
		'''
		return Response('', status = status.HTTP_200_OK)

	def patch(self, request, format = None):
		'''
		PATCH request.
		'''
		return Response('', status = status.HTTP_200_OK)

	def post(self, request, format = None):
		'''
		POST request.
		'''
		return Response('', status = status.HTTP_201_CREATED)

	def delete(self, request, format = None):
		'''
		DELETE request.
		'''
		return Response('', status = status.HTTP_204_NO_CONTENT)
