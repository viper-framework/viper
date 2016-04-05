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
# Partially derived from pyasn1 examples.

"""Subset of X.509 message syntax."""


from pyasn1.type import namedtype
from pyasn1.type import namedval
from pyasn1.type import tag
from pyasn1.type import univ

from x509_time import Time


class AttributeValue(univ.Any):
  pass


class AttributeType(univ.ObjectIdentifier):
  pass


class AttributeTypeAndValue(univ.Sequence):
  componentType = namedtype.NamedTypes(
      namedtype.NamedType('type', AttributeType()),
      namedtype.NamedType('value', AttributeValue()))


class RelativeDistinguishedName(univ.SetOf):
  componentType = AttributeTypeAndValue()


class RDNSequence(univ.SequenceOf):
  componentType = RelativeDistinguishedName()


class Name(univ.Choice):
  componentType = namedtype.NamedTypes(
      namedtype.NamedType('', RDNSequence()))


class AlgorithmIdentifier(univ.Sequence):
  componentType = namedtype.NamedTypes(
      namedtype.NamedType('algorithm', univ.ObjectIdentifier()),
      namedtype.OptionalNamedType('parameters', univ.Any()))


class Extension(univ.Sequence):
  componentType = namedtype.NamedTypes(
      namedtype.NamedType('extnID', univ.ObjectIdentifier()),
      namedtype.DefaultedNamedType('critical', univ.Boolean('False')),
      namedtype.NamedType('extnValue', univ.Any()))


class Extensions(univ.SequenceOf):
  componentType = Extension()


class SubjectPublicKeyInfo(univ.Sequence):
  componentType = namedtype.NamedTypes(
      namedtype.NamedType('algorithm', AlgorithmIdentifier()),
      namedtype.NamedType('subjectPublicKey', univ.BitString()))


class UniqueIdentifier(univ.BitString):
  pass


class Validity(univ.Sequence):
  componentType = namedtype.NamedTypes(
      namedtype.NamedType('notBefore', Time()),
      namedtype.NamedType('notAfter', Time()))


class CertificateSerialNumber(univ.Integer):
  pass


class Version(univ.Integer):
  namedValues = namedval.NamedValues(('v1', 0), ('v2', 1), ('v3', 2))


class TBSCertificate(univ.Sequence):
  """According to X.509 specification."""
  componentType = namedtype.NamedTypes(
      namedtype.DefaultedNamedType(
          'version', Version('v1', tagSet=Version.tagSet.tagExplicitly(tag.Tag(
              tag.tagClassContext, tag.tagFormatSimple, 0)))),
      namedtype.NamedType('serialNumber', CertificateSerialNumber()),
      namedtype.NamedType('signature', AlgorithmIdentifier()),
      namedtype.NamedType('issuer', Name()),
      namedtype.NamedType('validity', Validity()),
      namedtype.NamedType('subject', Name()),
      namedtype.NamedType('subjectPublicKeyInfo', SubjectPublicKeyInfo()),
      namedtype.OptionalNamedType(
          'issuerUniqueID', UniqueIdentifier().subtype(implicitTag=tag.Tag(
              tag.tagClassContext, tag.tagFormatSimple, 1))),
      namedtype.OptionalNamedType(
          'subjectUniqueID', UniqueIdentifier().subtype(implicitTag=tag.Tag(
              tag.tagClassContext, tag.tagFormatSimple, 2))),
      namedtype.OptionalNamedType('extensions', Extensions().subtype(
          explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))))


class Certificate(univ.Sequence):
  componentType = namedtype.NamedTypes(
      namedtype.NamedType('tbsCertificate', TBSCertificate()),
      namedtype.NamedType('signatureAlgorithm', AlgorithmIdentifier()),
      namedtype.NamedType('signatureValue', univ.BitString()))
