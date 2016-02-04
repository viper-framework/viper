#!/usr/bin/env python

# Copyright 2012 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Author: caronni@google.com (Germano Caronni)

"""X.509 Time class and utility functions.

   Limited interpretation of ASN.1 time formats,
   as specified in RFC2459, section 4.1.2.5
"""

import calendar
import time


from pyasn1 import error
from pyasn1.type import namedtype
from pyasn1.type import univ
from pyasn1.type import useful


class Time(univ.Choice):
  componentType = namedtype.NamedTypes(
      namedtype.NamedType('utcTime', useful.UTCTime()),
      namedtype.NamedType('generalTime', useful.GeneralizedTime()))

  def ToPythonEpochTime(self):
    """Takes a ASN.1 Time choice, and returns seconds since epoch in UTC."""
    utc_time = self.getComponentByName('utcTime')
    general_time = self.getComponentByName('generalTime')
    if utc_time and general_time:
      raise error.PyAsn1Error('Both elements of a choice are present.')
    if general_time:
      format_str = '%Y%m%d%H%M%SZ'
      time_str = str(general_time)
    else:
      format_str = '%y%m%d%H%M%SZ'
      time_str = str(utc_time)
    time_tpl = time.strptime(time_str, format_str)
    return calendar.timegm(time_tpl)
