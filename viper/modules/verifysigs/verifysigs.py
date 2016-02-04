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
# 
# Viper adaptation: jahrome11@gmail.com (Jerome Marty)



"""
    Wrapper to exercise fingerprinting and authenticode validation.
"""

# I really want to use parens in print statements.
# pylint: disable-msg=C6003

import hashlib
import pprint
import sys
import time


from pyasn1.codec.der import encoder as der_encoder

import auth_data
import fingerprint
import pecoff_blob
from asn1 import dn


# EVIL EVIL -- Monkeypatch to extend accessor
# TODO(user): This was submitted to pyasn1. Remove when we have it back.
def F(self, idx):
  if type(idx) is int:
    return self.getComponentByPosition(idx)
  else: return self.getComponentByName(idx)
from pyasn1.type import univ  # pylint: disable-msg=C6204,C6203
univ.SequenceAndSetBase.__getitem__ = F
del F, univ
# EVIL EVIL


def get_auth_data(filename):
  with file(filename, 'rb') as objf:
    fingerprinter = fingerprint.Fingerprinter(objf)
    is_pecoff = fingerprinter.EvalPecoff()
    fingerprinter.EvalGeneric()
    results = fingerprinter.HashIt()

  signed_pecoffs = [x for x in results if x['name'] == 'pecoff' and
                    'SignedData' in x]

  if not signed_pecoffs:
    print('This PE/COFF binary has no signature. Exiting.')
    return

  signed_pecoff = signed_pecoffs[0]
  signed_datas = signed_pecoff['SignedData']

  # There may be multiple of these, if the windows binary was signed multiple
  # times, e.g. by different entities. Each of them adds a complete SignedData
  # blob to the binary.
  # TODO(user): Process all instances
  signed_data = signed_datas[0]
  blob = pecoff_blob.PecoffBlob(signed_data)
  auth = auth_data.AuthData(blob.getCertificateBlob())
  content_hasher_name = auth.digest_algorithm().name
  computed_content_hash = signed_pecoff[content_hasher_name]

  return auth, computed_content_hash
