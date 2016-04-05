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

"""auth_data represents ASN.1 encoded Authenticode data.

   Provides high-level validators and accessor functions.
"""

import hashlib


from asn1 import dn
from asn1 import oids
from asn1 import pkcs7
from asn1 import spc

from pyasn1.codec.ber import decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.type import univ

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.backends import default_backend
    X509 = True
except ImportError:
    X509 = None


class Asn1Error(Exception):
  pass


def RequiresCryptography(fn):
  """Decorator to support limited functionality if cryptography is missing."""

  def CryptographyCheckingWrapper(*args, **kwargs):
    if not X509:
      raise Asn1Error('%s requires cryptography, which is not available', fn)
    return fn(*args, **kwargs)
  return CryptographyCheckingWrapper


# This is meant to hold the ASN.1 data representing all pieces
# of the parsed ASN.1 authenticode structure.
class AuthData(object):
  """Container for parsed ASN.1 structures out of Authenticode.

     Parsing is done at constructor time, after which caller can
     invoke validators, and access data structures.
  """

  container = None
  trailing_data = None
  signed_data = None
  digest_algorithm = None
  spc_info = None
  certificates = None
  signer_info = None
  signing_cert_id = None
  expected_spc_info_hash = None
  computed_auth_attrs_for_hash = None
  auth_attrs = None
  program_name = None
  program_url = None
  encrypted_digest = None
  has_countersignature = None
  counter_sig_info = None
  counter_sig_cert_id = None
  counter_attrs = None
  counter_timestamp = None
  computed_counter_attrs_for_hash = None
  expected_auth_attrs_hash = None
  encrypted_counter_digest = None
  openssl_error = None
  cert_chain_head = None
  counter_chain_head = None

  def __init__(self, content):
    self.container, rest = decoder.decode(content,
                                          asn1Spec=pkcs7.ContentInfo())
    if rest:
      self.trailing_data = rest

    self.signed_data, rest = decoder.decode(self.container['content'],
                                            asn1Spec=pkcs7.SignedData())
    if rest: raise Asn1Error('Extra unparsed content.')

    digest_algorithm_oid = self.signed_data['digestAlgorithms'][0]['algorithm']
    self.digest_algorithm = oids.OID_TO_CLASS.get(digest_algorithm_oid)

    spc_blob = self.signed_data['contentInfo']['content']
    self.spc_info, rest = decoder.decode(spc_blob,
                                         asn1Spec=spc.SpcIndirectDataContent())
    if rest: raise Asn1Error('Extra unparsed content.')
    # Currently not parsing the SpcIndirectDataContent 'data' field.
    # It used to contain information about the software publisher, but now
    # is set to default content, or under Vista+, may hold page hashes.

    self.certificates = self._ParseCerts(self.signed_data['certificates'])

    self.signer_info = self.signed_data['signerInfos'][0]

    self.signing_cert_id = self._ParseIssuerInfo(
        self.signer_info['issuerAndSerialNumber'])

    # Parse out mandatory fields in authenticated attributes.
    self.auth_attrs, self.computed_auth_attrs_for_hash = (
        self._ParseAuthAttrs(self.signer_info['authenticatedAttributes'],
                             required=[pkcs7.ContentType,
                                       pkcs7.DigestInfo,
                                       spc.SpcSpOpusInfo]))
    hashval, rest = decoder.decode(self.auth_attrs[pkcs7.DigestInfo][0])
    if rest: raise Asn1Error('Extra unparsed content.')
    if hashval.__class__ is not univ.OctetString:
      raise Asn1Error('Hash value expected to be OctetString.')
    self.expected_spc_info_hash = str(hashval)

    opus_info_asn1 = self.auth_attrs[spc.SpcSpOpusInfo][0]
    self.program_name, self.program_url = self._ParseOpusInfo(opus_info_asn1)

    self.encrypted_digest = str(self.signer_info['encryptedDigest'])

    unauth_attrs = self.signer_info['unauthenticatedAttributes']
    if unauth_attrs is None:
      self.has_countersignature = False
      return

    self.has_countersignature = True
    self.counter_sig_info = self._ParseCountersig(unauth_attrs)
    self.counter_sig_cert_id = self._ParseIssuerInfo(
        self.counter_sig_info['issuerAndSerialNumber'])

    # Parse out mandatory fields in countersig authenticated attributes.
    self.counter_attrs, self.computed_counter_attrs_for_hash = (
        self._ParseAuthAttrs(self.counter_sig_info['authenticatedAttributes'],
                             required=[pkcs7.ContentType,
                                       pkcs7.SigningTime,
                                       pkcs7.DigestInfo]))

    hashval, rest = decoder.decode(self.counter_attrs[pkcs7.DigestInfo][0])
    if rest: raise Asn1Error('Extra unparsed content.')
    if hashval.__class__ is not univ.OctetString:
      raise Asn1Error('Hash value expected to be OctetString.')
    self.expected_auth_attrs_hash = str(hashval)

    self.counter_timestamp = self._ParseTimestamp(
        self.counter_attrs[pkcs7.SigningTime][0])

    self.encrypted_counter_digest = str(
        self.counter_sig_info['encryptedDigest'])

  def _ParseTimestamp(self, time_asn1):
    # Parses countersignature timestamp according to RFC3280, section 4.1.2.5+
    timestamp_choice, rest = decoder.decode(time_asn1,
                                            asn1Spec=pkcs7.SigningTime())
    if rest: raise Asn1Error('Extra unparsed content.')
    return timestamp_choice.ToPythonEpochTime()

  def _ParseIssuerInfo(self, issuer_and_serial):
    # Extract the information that identifies the certificate to be
    # used for verification on the encryptedDigest in signer_info
    # TODO(user): there is probably more validation to be done on these
    # fields.
    issuer = issuer_and_serial['issuer']
    serial_number = int(issuer_and_serial['serialNumber'])
    issuer_dn = str(dn.DistinguishedName.TraverseRdn(issuer[0]))
    return (issuer_dn, serial_number)

  def _ParseOpusInfo(self, opus_info_asn1):
    spc_opus_info, rest = decoder.decode(opus_info_asn1,
                                         asn1Spec=spc.SpcSpOpusInfo())
    if rest: raise Asn1Error('Extra unparsed content.')

    if spc_opus_info['programName']:
      # According to spec, this should always be a Unicode string. However,
      # the ASN.1 syntax allows both ASCII and Unicode. So, let's be careful.
      opus_prog_name = spc_opus_info['programName']
      uni_name = opus_prog_name['unicode']
      ascii_name = opus_prog_name['ascii']
      if ascii_name and uni_name:
        # WTF? This is supposed to be a CHOICE
        raise Asn1Error('Both elements of a choice are present.')
      elif uni_name:
        program_name = str(uni_name).decode('utf-16-be')
      elif ascii_name:
        program_name = str(ascii_name)
      else:
        raise Asn1Error('No element of opusInfo choice is present.')
    else:
      # According to spec, there should always be a program name,
      # and be it zero-length. But let's be gentle, since ASN.1 marks
      # this field als optional.
      program_name = None

    # Again, according to Authenticode spec, the moreInfo field should always
    # be there and point to an ASCII string with a URL.
    if spc_opus_info['moreInfo']:
      more_info = spc_opus_info['moreInfo']
      if more_info['url']:
        more_info_link = str(more_info['url'])
      else:
        raise Asn1Error('Expected a URL in moreInfo.')
    else:
      more_info_link = None

    return program_name, more_info_link

  def _ExtractIssuer(self, cert):
    issuer = cert[0][0]['issuer']
    serial_number = int(cert[0][0]['serialNumber'])
    issuer_dn = str(dn.DistinguishedName.TraverseRdn(issuer[0]))
    return (issuer_dn, serial_number)

  def _ParseCerts(self, certs):
    # TODO(user):
    # Parse them into a dict with serial, subject dn, issuer dn, lifetime,
    # algorithm, x509 version, extensions, ...
    res = dict()
    for cert in certs:
      res[self._ExtractIssuer(cert)] = cert
    return res

  def _ParseCountersig(self, unauth_attrs):
    attr = unauth_attrs[0]
    if oids.OID_TO_CLASS.get(attr['type']) is not pkcs7.CountersignInfo:
      raise Asn1Error('Unexpected countersign OID.')
    values = attr['values']
    if len(values) != 1:
      raise Asn1Error('Expected one CS value, got %d.' % len(values))
    counter_sig_info, rest = decoder.decode(values[0],
                                            asn1Spec=pkcs7.CountersignInfo())
    if rest: raise Asn1Error('Extra unparsed content.')
    return counter_sig_info

  def _ParseAuthAttrs(self, auth_attrs, required):
    results = dict.fromkeys(required)
    for attr in auth_attrs:
      if (attr['type'] in oids.OID_TO_CLASS and
          oids.OID_TO_CLASS.get(attr['type']) in required):
        # There are more than those I require, but I don't know what they are,
        # and what to do with them. The spec does not talk about them.
        # One example:
        # 1.3.6.1.4.1.311.2.1.11 contains as value 1.3.6.1.4.1.311.2.1.21
        # SPC_STATEMENT_TYPE_OBJID    SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID
        results[oids.OID_TO_CLASS.get(attr['type'])] = attr['values']
    if None in results.itervalues():
      raise Asn1Error('Missing mandatory field(s) in auth_attrs.')

    # making sure that the auth_attrs were processed in correct order
    # they need to be sorted in ascending order in the SET, when DER encoded
    # This also makes sure that the tag on Attributes is correct.
    a = [der_encoder.encode(i) for i in auth_attrs]
    a.sort()
    attrs_for_hash = pkcs7.Attributes()
    for i in range(len(auth_attrs)):
      d, _ = decoder.decode(a[i], asn1Spec=pkcs7.Attribute())
      attrs_for_hash.setComponentByPosition(i, d)
    encoded_attrs = der_encoder.encode(attrs_for_hash)

    return results, encoded_attrs

  def _ValidateEmptyParams(self, params):
    if params:
      param_value, rest = decoder.decode(params)
      if rest:
        raise Asn1Error('Extra unparsed content.')
      if param_value != univ.Null():
        raise Asn1Error('Hasher has parameters. No idea what to do with them.')

  def ValidateAsn1(self):
    """Validate overall information / consistency.

    Can be invoked to check through most of the assumptions on
    ASN.1 integrity, and constraints placed on PKCS#7 / X.509 by
    Authenticode.

    Returns:
      Nothing.

    Raises:
      Asn1Error: with a descriptive string, if anything is amiss.
    """

    # Validate overall information
    if (oids.OID_TO_CLASS.get(self.container['contentType']) is not
        pkcs7.SignedData):
      raise Asn1Error('Unexpected OID: %s' %
                      self.container['contentType'].prettyPrint())
    if self.signed_data['version'] != 1:
      raise Asn1Error('SignedData wrong version: %s' %
                      self.signed_data['version'].prettyPrint())

    # Validate content digest specs.
    if len(self.signed_data['digestAlgorithms']) != 1:
      raise Asn1Error('Expected exactly one digestAlgorithm, got %d.' %
                      len(self.signed_data['digestAlgorithms']))
    spec = self.signed_data['digestAlgorithms'][0]
    if (self.digest_algorithm is not hashlib.md5 and
        self.digest_algorithm is not hashlib.sha1):
      raise Asn1Error('digestAlgorithm must be md5 or sha1, was %s.' %
                      spec['algorithm'].prettyPrint())
    self._ValidateEmptyParams(spec['parameters'])

    # Validate SpcIndirectDataContent structure
    oid = self.signed_data['contentInfo']['contentType']
    if oids.OID_TO_CLASS.get(oid) is not spc.SpcIndirectDataContent:
      raise Asn1Error('Unexpected contentInfo OID: %s' % oid.prettyPrint())

    # Validate content hash meta data in spcIndirectDataContent
    oid = self.spc_info['messageDigest']['digestAlgorithm']['algorithm']
    if oids.OID_TO_CLASS.get(oid) is not self.digest_algorithm:
      raise Asn1Error('Outer and SPC message_digest algorithms don\'t match.')
    params = self.spc_info['messageDigest']['digestAlgorithm']['parameters']
    self._ValidateEmptyParams(params)

    if self.signed_data['crls']:
      raise Asn1Error('Don\'t know what to do with CRL information.')

    # Work through signer_info pieces that are easily validated
    if len(self.signed_data['signerInfos']) != 1:
      raise Asn1Error('Expected one signer_info, got %d.' %
                      len(self.signed_data['signerInfos']))
    if self.signer_info['version'] != 1:
      raise Asn1Error('SignerInfo wrong version: %s' %
                      self.signer_info['version'].prettyPrint())

    # Make sure signer_info hash algorithm is consistent
    oid = self.signer_info['digestAlgorithm']['algorithm']
    if oids.OID_TO_CLASS.get(oid) is not self.digest_algorithm:
      raise Asn1Error('Outer and signer_info digest algorithms don\'t match.')
    params = self.signer_info['digestAlgorithm']['parameters']
    self._ValidateEmptyParams(params)

    # Make sure the signing cert is actually in the list of certs
    if self.signing_cert_id not in self.certificates:
      raise Asn1Error('Signing cert not in list of known certificates.')

    # auth_attrs has three fields, where we do some integrity / sanity checks
    # content_type
    content_type_set = self.auth_attrs[pkcs7.ContentType]
    if len(content_type_set) != 1:
      raise Asn1Error('authAttr.content_type expected to hold one value.')
    content_type, rest = decoder.decode(content_type_set[0])
    if rest:
      raise Asn1Error('Extra unparsed content.')
    # Spec claims this should be messageDigestOID, but that's not true.
    if oids.OID_TO_CLASS.get(content_type) is not spc.SpcIndirectDataContent:
      raise Asn1Error('Unexpected authAttr.content_type OID: %s' %
                      content_type.prettyPrint())
    # Message_digest -- 'just' an octet string
    message_digest_set = self.auth_attrs[pkcs7.DigestInfo]
    if len(message_digest_set) != 1:
      raise Asn1Error('authAttr.messageDigest expected to hold one value.')
    _, rest = decoder.decode(message_digest_set[0])
    if rest:
      raise Asn1Error('Extra unparsed content.')
    # opusInfo -- has it's own section

    enc_alg = self.signer_info['digestEncryptionAlgorithm']['algorithm']
    if enc_alg not in oids.OID_TO_PUBKEY:
      raise Asn1Error('Could not parse digestEncryptionAlgorithm.')
    params = self.signer_info['digestEncryptionAlgorithm']['parameters']
    self._ValidateEmptyParams(params)

    if not self.has_countersignature: return

    unauth_attrs = self.signer_info['unauthenticatedAttributes']
    if len(unauth_attrs) != 1:
      raise Asn1Error('Expected one attribute, got %d.' % len(unauth_attrs))
    # Extra structure parsed in _ParseCountersig

    # signer_info of the counter signature
    if self.counter_sig_info['version'] != 1:
      raise Asn1Error('Countersignature wrong version: %s' %
                      self.counter_sig_info['version'].prettyPrint())

    # Make sure counter_sig_info hash algorithm is consistent
    oid = self.counter_sig_info['digestAlgorithm']['algorithm']
    if oids.OID_TO_CLASS.get(oid) is not self.digest_algorithm:
      raise Asn1Error('Outer and countersign digest algorithms don\'t match.')
    params = self.counter_sig_info['digestAlgorithm']['parameters']
    self._ValidateEmptyParams(params)

    # Make sure the counter-signing cert is actually in the list of certs
    if self.counter_sig_cert_id not in self.certificates:
      raise Asn1Error('Countersigning cert not in list of known certificates.')

    # counterSig auth_attrs also has three fields, where we do some
    # integrity / sanity checks
    # content_type
    content_type_set = self.counter_attrs[pkcs7.ContentType]
    if len(content_type_set) != 1:
      raise Asn1Error('counterAttr.content_type expected to hold one value.')
    content_type, rest = decoder.decode(content_type_set[0])
    if rest:
      raise Asn1Error('Extra unparsed content.')
    if oids.OID_TO_CLASS.get(content_type) != 'PKCS#7 Data':
      raise Asn1Error('Unexpected counterAttr.content_type OID: %s' %
                      content_type.prettyPrint())
    # message_digest -- 'just' an octet string
    message_digest_set = self.counter_attrs[pkcs7.DigestInfo]
    if len(message_digest_set) != 1:
      raise Asn1Error('counterAttr.message_digest expected to hold one value.')
    _, rest = decoder.decode(message_digest_set[0])
    if rest:
      raise Asn1Error('Extra unparsed content.')
    # TODO(user): Check SigningTime integrity
    # e.g. only one value in the set

    enc_alg = self.counter_sig_info['digestEncryptionAlgorithm']['algorithm']
    if enc_alg not in oids.OID_TO_PUBKEY:
      raise Asn1Error('Could not parse CS digestEncryptionAlgorithm.')
    params = self.counter_sig_info['digestEncryptionAlgorithm']['parameters']
    self._ValidateEmptyParams(params)

  def ValidateHashes(self, computed_content_hash):
    """Compares computed against expected hashes.

    This method makes sure the chain of hashes is correct. The chain
    consists of Authenticode hash of the actual binary payload, as checked
    against the hash in SpcInfo to the hash of SpcInfo as stored in the
    AuthAttrs, and the hash of EncryptedDigest as stored in the counter-
    signature AuthAttrs, if present.

    Args:
      computed_content_hash: Authenticode hash of binary, as provided by
                             fingerprinter.
    Raises:
      Asn1Error: if hash validation fails.
    """

    if computed_content_hash != self.spc_info['messageDigest']['digest']:
      raise Asn1Error('1: Validation of content hash failed.')

    spc_blob = self.signed_data['contentInfo']['content']
    # According to RFC2315, 9.3, identifier (tag) and length need to be
    # stripped for hashing. We do this by having the parser just strip
    # out the SEQUENCE part of the spcIndirectData.
    # Alternatively this could be done by re-encoding and concatenating
    # the individual elements in spc_value, I _think_.
    _, hashable_spc_blob = decoder.decode(spc_blob, recursiveFlag=0)
    spc_blob_hash = self.digest_algorithm(str(hashable_spc_blob)).digest()
    if spc_blob_hash != self.expected_spc_info_hash:
      raise Asn1Error('2: Validation of SpcInfo hash failed.')
    # Can't check authAttr hash against encrypted hash, done implicitly in
    # M2's pubkey.verify. This can be added by explicit decryption of
    # encryptedDigest, if really needed. (See sample code for RSA in
    # 'verbose_authenticode_sig.py')

    if self.has_countersignature:
      # Validates the hash value found in the authenticated attributes of the
      # counter signature against the hash of the outer signature.
      auth_attr_hash = self.digest_algorithm(self.encrypted_digest).digest()
      if auth_attr_hash != self.expected_auth_attrs_hash:
        raise Asn1Error('3: Validation of countersignature hash failed.')

  def ValidateCertChains(self, timestamp):  # pylint: disable-msg=W0613
    # TODO(user):
    # Check ASN.1 on the certs
    # Check designated certificate use
    # Check extension consistency
    # Check wether timestamping is prohibited
    not_before, not_after, top_cert = self._ValidateCertChain(
        self.certificates[self.signing_cert_id])
    self.cert_chain_head = (not_before, not_after,
                            self._ExtractIssuer(top_cert))

    if self.has_countersignature:
      cs_not_before, cs_not_after, cs_top_cert = self._ValidateCertChain(
          self.certificates[self.counter_sig_cert_id])
      self.counter_chain_head = (cs_not_before, cs_not_after,
                                 self._ExtractIssuer(cs_top_cert))
      # Time of countersignature needs to be within validity of both chains
      if (not_before > self.counter_timestamp > not_after or
          cs_not_before > self.counter_timestamp > cs_not_after):
        raise Asn1Error('Cert chain not valid at countersig time.')
    else:
      # Check if certificate chain was valid at time 'timestamp'
      if timestamp:
        if not_before > timestamp > not_after:
          raise Asn1Error('Cert chain not valid at time timestamp.')

  def _ValidateCertChain(self, signee):
    # Get start of 'regular' chain
    not_before = signee[0][0]['validity']['notBefore'].ToPythonEpochTime()
    not_after = signee[0][0]['validity']['notAfter'].ToPythonEpochTime()
    while True:
      issuer = signee[0][0]['issuer']
      issuer_dn = str(dn.DistinguishedName.TraverseRdn(issuer[0]))
      signer = None
      for cert in self.certificates.values():
        subject = cert[0][0]['subject']
        subject_dn = str(dn.DistinguishedName.TraverseRdn(subject[0]))
        if subject_dn == issuer_dn:
          signer = cert
      # Are we at the end of the chain?
      if not signer:
        break
      self.ValidateCertificateSignature(signee, signer)
      # Did we hit a self-signed certificate?
      if signee == signer:
        break
      t_not_before = signer[0][0]['validity']['notBefore'].ToPythonEpochTime()
      t_not_after = signer[0][0]['validity']['notAfter'].ToPythonEpochTime()
      if t_not_before > not_before:
        # why would a cert be signed with something that was not valid yet
        # just silently absorbing this case for now
        not_before = t_not_before
      not_after = min(not_after, t_not_after)
      # Now let's go up a step in the cert chain.
      signee = signer
    return not_before, not_after, signee

  @RequiresCryptography
  def _ValidatePubkeyGeneric(self, signing_cert, digest_alg, payload,
                             enc_digest):
    cert = x509.load_der_x509_certificate(der_encoder.encode(signing_cert), default_backend())
    pubkey = cert.public_key()
    if isinstance(pubkey, RSAPublicKey):
        verifier = pubkey.verifier(enc_digest, padding.PKCS1v15(), cert.signature_hash_algorithm)
    else:
        verifier = pubkey.verifier(enc_digest, cert.signature_hash_algorithm)
    verifier.update(payload)
    try:
        verifier.verify()
        return True
    except:
        return False

  @RequiresCryptography
  def ValidateCertificateSignature(self, signed_cert, signing_cert):
    """Given a cert signed by another cert, validates the signature."""
    # First the naive way -- note this does not check expiry / use etc.
    signed = x509.load_der_x509_certificate(der_encoder.encode(signed_cert), default_backend())
    signing = x509.load_der_x509_certificate(der_encoder.encode(signing_cert), default_backend())
    verifier = signing.public_key().verifier(signed.signature, padding.PKCS1v15(), signed.signature_hash_algorithm)
    verifier.update(signed.tbs_certificate_bytes)
    try:
        verifier.verify()
    except Exception as e:
        raise Asn1Error('1: Validation of cert signature failed: {}'.format(e))

  def ValidateSignatures(self):
    """Validate encrypted hashes with respective public keys.

    Invokes necessary public key operations to check that signatures
    on authAttr hashes are correct for both the basic signature, and
    if present the countersignature.

    Raises:
      Asn1Error: if signature validation fails.
    """
    # Encrypted digest is that of auth_attrs, see comments in ValidateHashes.
    signing_cert = self.certificates[self.signing_cert_id]
    v = self._ValidatePubkeyGeneric(signing_cert, self.digest_algorithm,
                                    self.computed_auth_attrs_for_hash,
                                    self.encrypted_digest)
    if not v:
      raise Asn1Error('1: Validation of basic signature failed.')

    if self.has_countersignature:
      signing_cert = self.certificates[self.counter_sig_cert_id]
      v = self._ValidatePubkeyGeneric(signing_cert, self.digest_algorithm,
                                      self.computed_counter_attrs_for_hash,
                                      self.encrypted_counter_digest)
      if not v:
        raise Asn1Error('2: Validation of counterSignature failed.')
