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

"""Subset of PKCS#7 message syntax."""


from pyasn1.type import namedtype
from pyasn1.type import tag
from pyasn1.type import univ
import x509
from x509_time import Time


class Attribute(univ.Sequence):
  componentType = namedtype.NamedTypes(
      namedtype.NamedType('type', x509.AttributeType()),
      namedtype.NamedType('values', univ.SetOf(
          componentType=x509.AttributeValue())))


class ContentType(univ.ObjectIdentifier):
  pass


class Version(univ.Integer):
  pass


class DigestAlgorithmIdentifier(x509.AlgorithmIdentifier):
  pass


class DigestAlgorithmIdentifiers(univ.SetOf):
  componentType = DigestAlgorithmIdentifier()


class Digest(univ.OctetString):
  pass


class DigestInfo(univ.Sequence):
  componentType = namedtype.NamedTypes(
      namedtype.NamedType('digestAlgorithm', DigestAlgorithmIdentifier()),
      namedtype.NamedType('digest', Digest()))


class ContentInfo(univ.Sequence):
  componentType = namedtype.NamedTypes(
      namedtype.NamedType('contentType', ContentType()),
      namedtype.OptionalNamedType('content', univ.Any().subtype(
          explicitTag=tag.Tag(tag.tagClassContext,
                              tag.tagFormatConstructed, 0))))


class IssuerAndSerialNumber(univ.Sequence):
  componentType = namedtype.NamedTypes(
      namedtype.NamedType('issuer', x509.Name()),
      namedtype.NamedType('serialNumber', x509.CertificateSerialNumber()))


class Attributes(univ.SetOf):
  componentType = Attribute()


class ExtendedCertificateInfo(univ.Sequence):
  componentType = namedtype.NamedTypes(
      namedtype.NamedType('version', Version()),
      namedtype.NamedType('certificate', x509.Certificate()),
      namedtype.NamedType('attributes', Attributes()))


class SignatureAlgorithmIdentifier(x509.AlgorithmIdentifier):
  pass


class Signature(univ.BitString):
  pass


class ExtendedCertificate(univ.Sequence):
  componentType = namedtype.NamedTypes(
      namedtype.NamedType('extendedCertificateInfo', ExtendedCertificateInfo()),
      namedtype.NamedType('signatureAlgorithm', SignatureAlgorithmIdentifier()),
      namedtype.NamedType('signature', Signature()))


class ExtendedCertificateOrCertificate(univ.Choice):
  componentType = namedtype.NamedTypes(
      namedtype.NamedType('certificate', x509.Certificate()),
      namedtype.NamedType('extendedCertificate', ExtendedCertificate().subtype(
          implicitTag=tag.Tag(tag.tagClassContext,
                              tag.tagFormatConstructed, 0))))


class ExtendedCertificatesAndCertificates(univ.SetOf):
  componentType = ExtendedCertificateOrCertificate()


class SerialNumber(univ.Integer):
  pass


class CertificateRevocationLists(univ.Any):
  pass


class DigestEncryptionAlgorithmIdentifier(x509.AlgorithmIdentifier):
  pass


class EncryptedDigest(univ.OctetString):
  pass


class SignerInfo(univ.Sequence):
  """As defined by PKCS#7."""
  componentType = namedtype.NamedTypes(
      namedtype.NamedType('version', Version()),
      namedtype.NamedType('issuerAndSerialNumber', IssuerAndSerialNumber()),
      namedtype.NamedType('digestAlgorithm', DigestAlgorithmIdentifier()),
      namedtype.OptionalNamedType(
          'authenticatedAttributes', Attributes().subtype(implicitTag=tag.Tag(
              tag.tagClassContext, tag.tagFormatConstructed, 0))),
      namedtype.NamedType('digestEncryptionAlgorithm',
                          DigestEncryptionAlgorithmIdentifier()),
      namedtype.NamedType('encryptedDigest', EncryptedDigest()),
      namedtype.OptionalNamedType('unauthenticatedAttributes',
                                  Attributes().subtype(implicitTag=tag.Tag(
                                      tag.tagClassContext,
                                      tag.tagFormatConstructed, 1))))


class SignerInfos(univ.SetOf):
  componentType = SignerInfo()


class SignedData(univ.Sequence):
  """As defined by PKCS#7."""
  componentType = namedtype.NamedTypes(
      namedtype.NamedType('version', Version()),
      namedtype.NamedType('digestAlgorithms', DigestAlgorithmIdentifiers()),
      namedtype.NamedType('contentInfo', ContentInfo()),
      namedtype.OptionalNamedType(
          'certificates', ExtendedCertificatesAndCertificates().subtype(
              implicitTag=tag.Tag(tag.tagClassContext,
                                  tag.tagFormatConstructed, 0))),
      namedtype.OptionalNamedType('crls', CertificateRevocationLists().subtype(
          implicitTag=tag.Tag(tag.tagClassContext,
                              tag.tagFormatConstructed, 1))),
      namedtype.NamedType('signerInfos', SignerInfos()))


class CountersignInfo(SignerInfo):
  pass


class SigningTime(Time):
  pass
