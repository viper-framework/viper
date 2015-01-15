#!/usr/bin/env python

# Copyright 2011 Google Inc. All Rights Reserved.
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

"""dn converts ASN.1 Distinguished Names to strings.

   TODO(user): TraverseRdn should build a better string representation,
   see comments below. RFC2253 provides the right way to do this. Instead of
   returning a dict, return a string.
   May also want an inverse function, parsing a string into an RDN sequence.
"""


from pyasn1.codec.ber import decoder


class DistinguishedName(object):
  """Container for relevant OIDs and static conversion methods."""

  # I want the formatting to make sense and be readable, really.
  # pylint: disable-msg=C6007
  OIDs = {
      (2, 5, 4, 3)                       : 'CN',   # common name
      (2, 5, 4, 6)                       : 'C',    # country
      (2, 5, 4, 7)                       : 'L',    # locality
      (2, 5, 4, 8)                       : 'ST',   # stateOrProvince
      (2, 5, 4, 10)                      : 'O',    # organization
      (2, 5, 4, 11)                      : 'OU',   # organizationalUnit
      (0, 9, 2342, 19200300, 100, 1, 25) : 'DC',   # domainComponent
      (1, 2, 840, 113549, 1, 9, 1)       : 'EMAIL',# emailaddress
  }
  # pylint: enable-msg=C6007

  @staticmethod
  def OidToName(oid):
    return DistinguishedName.OIDs.get(oid, str(oid))

  @staticmethod
  def TraverseRdn(rdn):
    """Traverses RDN structure and returns string encoding of the DN.

    Args:
      rdn: ASN.1 SET (or SEQUENCE) containing RDNs (relative distinguished
           names), as identified by type / value pairs. A typical input would
          be of type X.509 RelativeDistinguishedName.

    Returns:
      A dict representing the Distinguished Name.
    """
    val = dict()
    for n in rdn:
      # Note that this does not work for e.g. DC which is present
      # multiple times.
      # For a real DN parser, make sure to follow the spec in regards
      # to multiple occurence of a field in subsequent RDNs, maintaining
      # original ordering etc.
      # TODO(user): What about elements other than [0]??
      name = DistinguishedName.OidToName(n[0]['type'])
      value = decoder.decode(n[0]['value'])
      if name in val:
        val[name] = str(value[0]) + ', ' + val.get(name, '')
      else:
        val[name] = str(value[0])
    return val
