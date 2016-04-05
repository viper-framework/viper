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

"""ASN.1 OIDs mappings to parser classes or strings, where there is no class."""

import hashlib


import pkcs7
import spc

# I want the formatting to make sense and be readable, really.
# pylint: disable-msg=C6006,C6007
OID_TO_CLASS = {
    (1,2,840,113549,1,7,1)   : 'PKCS#7 Data',
    (1,2,840,113549,1,7,2)   : pkcs7.SignedData,
    (1,2,840,113549,2,5)     : hashlib.md5,
    (1,3,14,3,2,26)          : hashlib.sha1,
    (1,3,6,1,4,1,311,2,1,4)  : spc.SpcIndirectDataContent,
    (1,2,840,113549,1,9,3)   : pkcs7.ContentType,
    (1,2,840,113549,1,9,4)   : pkcs7.DigestInfo,
    (1,3,6,1,4,1,311,2,1,12) : spc.SpcSpOpusInfo,
    (1,2,840,113549,1,9,6)   : pkcs7.CountersignInfo,  # 'RSA_counterSign'
    (1,2,840,113549,1,9,5)   : pkcs7.SigningTime,
}

OID_TO_PUBKEY = {
    (1,2,840,113549,1,1,1)   : 'rsa',
    (1,2,840,113549,1,1,5)   : 'rsa-sha1',
    (1,2,840,10040,4,1)      : 'dsa',
}
