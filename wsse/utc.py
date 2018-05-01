# wsse/utc.py
# coding=utf-8
# pywsse
# Author: Rushy Panchal
# Date: May 1st, 2018
# Description: UTC timezone declaration.
# See: https://docs.python.org/2/library/datetime.html#tzinfo-objects.

import datetime

_zero = datetime.timedelta(0)
class _UTC(datetime.tzinfo):
  """UTC Timezone Info."""
  def utcoffset(self, dt):
    return _zero

  def tzname(self, dt):
    return "UTC"

  def dst(self, dt):
    return _zero
  
utc = _UTC()
