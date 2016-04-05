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

"""Deal with Microsoft-specific Authenticode data."""

# Comments and constant names as extracted from pecoff_v8 specs.
# Variable names are also used as defined in the PECOFF specification.
# pylint: disable-msg=C6409

# Version 1, legacy version of Win_Certificate structure. It is supported
# only for purposes of verifying legacy Authenticode signatures.
WIN_CERT_REVISION_1_0 = 0x100

# Version 2 is the current version of the Win_Certificate structure. 
WIN_CERT_REVISION_2_0 = 0x200

# Only type PKCS is supported by the pecoff specification.
WIN_CERT_TYPE_X509 = 1
WIN_CERT_TYPE_PKCS_SIGNED_DATA = 2
WIN_CERT_TYPE_RESERVED_1 = 3
WIN_CERT_TYPE_TS_STACK_SIGNED = 4


class PecoffBlob(object):
  """Encapsulating class for Microsoft-specific Authenticode data.

  As defined in the PECOFF (v8) and Authenticode specifications.
  This is data as it is extracted from the signature_data field by
  the fingerprinter.
  """

  def __init__(self, signed_data_tuple):
    self._wRevision = signed_data_tuple[0]
    self._wCertificateType = signed_data_tuple[1]
    self._bCertificate = signed_data_tuple[2]

    if self._wRevision != WIN_CERT_REVISION_2_0:
      raise RuntimeError("Unknown revision %#x." % self._wRevision)
    if self._wCertificateType != WIN_CERT_TYPE_PKCS_SIGNED_DATA:
      raise RuntimeError("Unknown cert type %#x." % self._wCertificateType)

  def getCertificateBlob(self):
    return self._bCertificate
