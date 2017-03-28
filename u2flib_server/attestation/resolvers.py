# Copyright (c) 2013 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

from u2flib_server.attestation.model import MetadataObject
from u2flib_server.attestation.data import YUBICO
import six
import os
import json

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding

__all__ = ['MetadataResolver', 'create_resolver']


class MetadataResolver(object):

    def __init__(self):
        self._identifiers = {}  # identifier -> Metadata
        self._certs = {}  # Subject -> Cert
        self._metadata = {}  # Cert -> Metadata

    def add_metadata(self, metadata):
        metadata = MetadataObject.wrap(metadata)

        if metadata.identifier in self._identifiers:
            existing = self._identifiers[metadata.identifier]
            if metadata.version <= existing.version:
                return  # Older version
            else:
                # Re-index everything
                self._identifiers[metadata.identifier] = metadata
                self._certs.clear()
                self._metadata.clear()
                for metadata in self._identifiers.values():
                    self._index(metadata)
        else:
            self._identifiers[metadata.identifier] = metadata
            self._index(metadata)

    def _index(self, metadata):
        for cert_pem in metadata.trustedCertificates:
            if isinstance(cert_pem, six.text_type):
                cert_pem = cert_pem.encode('ascii')
            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
            subject = cert.subject \
                .get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            self._certs.setdefault(subject, []).append(cert)
            self._metadata[cert] = metadata

    def _verify_cert(self, cert, pubkey):
        """Returns True if cert contains a correct signature made using the
        provided key

        NB: This *only* checks the signature. No other checks are performed.
        E.g. the trust chain, expiry are all ignored.
        """
        cert_signature = cert.signature
        cert_bytes = cert.tbs_certificate_bytes

        if isinstance(pubkey, rsa.RSAPublicKey):
            verifier = pubkey.verifier(
                cert_signature,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
        elif isinstance(pubkey, ec.EllipticCurvePublicKey):
            verifier = pubkey.verifier(
                cert_signature,
                ec.ECDSA(cert.signature_hash_algorithm)
            )
        else:
            raise ValueError("Unsupported public key value")

        verifier.update(cert_bytes)

        try:
            verifier.verify()
            return True
        except InvalidSignature:
            return False

    def resolve(self, cert):
        if isinstance(cert, bytes):
            cert = x509.load_der_x509_certificate(cert, default_backend())
        issuer = cert.issuer \
            .get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

        for issuer in self._certs.get(issuer, []):
            if self._verify_cert(cert, issuer.public_key()):
                return self._metadata[issuer]
        return None


def _load_from_file(fname):
    with open(fname, 'r') as f:
        return json.load(f)


def _load_from_dir(dname):
    json_fnames = [os.path.join(dname, d) for d in os.listdir(dname)
                   if d.endswith('.json')]
    return [_load_from_file(fname) for fname in json_fnames]


def _add_data(resolver, data):
    if isinstance(data, list):
        for d in data:
            _add_data(resolver, d)
        return
    elif isinstance(data, six.string_types):
        if os.path.isdir(data):
            data = _load_from_dir(data)
        elif os.path.isfile(data):
            data = _load_from_file(data)
        return _add_data(resolver, data)
    if data is not None:
        resolver.add_metadata(data)


def create_resolver(data=None):
    resolver = MetadataResolver()
    if data is None:
        data = YUBICO
    _add_data(resolver, data)
    return resolver
