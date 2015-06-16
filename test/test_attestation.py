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

from u2flib_server.attestation.metadata import MetadataProvider
from u2flib_server.attestation.resolvers import create_resolver
from u2flib_server.attestation.data import YUBICO
from M2Crypto import X509
import json
import unittest

ATTESTATION_CERT = """
MIICGzCCAQWgAwIBAgIEdaP2dTALBgkqhkiG9w0BAQswLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBS
b290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBa
MCoxKDAmBgNVBAMMH1l1YmljbyBVMkYgRUUgU2VyaWFsIDE5NzM2Nzk3MzMwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAAQZo35Damtpl81YdmcbhEuXKAr7xDcQzAy5n3ftAAhtBbu8EeGU4ynfSgLo
nckqX6J2uXLBppTNE3v2bt+Yf8MLoxIwEDAOBgorBgEEAYLECgECBAAwCwYJKoZIhvcNAQELA4IB
AQC9LbiNPgs0sQYOHAJcg+lMk+HCsiWRlYVnbT4I/5lnqU907vY17XYAORd432bU3Nnhsbkvjz76
kQJGXeNAF4DPANGGlz8JU+LNEVE2PWPGgEM0GXgB7mZN5Sinfy1AoOdO+3c3bfdJQuXlUxHbo+nD
pxxKpzq9gr++RbokF1+0JBkMbaA/qLYL4WdhY5NvaOyMvYpO3sBxlzn6FcP67hlotGH1wU7qhCeh
+uur7zDeAWVh7c4QtJOXHkLJQfV3Z7ZMvhkIA6jZJAX99hisABU/SSa5DtgX7AfsHwa04h69AAAW
DUzSk3HgOXbUd1FaSOPdlVFkG2N2JllFHykyO3zO
""".replace('\n', '').decode('base64')


class AttestationTest(unittest.TestCase):

    def test_resolver(self):
        resolver = create_resolver(YUBICO)
        cert = X509.load_cert_der_string(ATTESTATION_CERT)

        metadata = resolver.resolve(cert)
        assert metadata.identifier == '2fb54029-7613-4f1d-94f1-fb876c14a6fe'

    def test_provider(self):
        provider = MetadataProvider()
        cert = X509.load_cert_der_string(ATTESTATION_CERT)
        attestation = provider.get_attestation(cert)

        assert attestation.trusted

    def test_versioning_newer(self):
        resolver = create_resolver(YUBICO)
        newer = json.loads(json.dumps(YUBICO))
        newer['version'] = newer['version'] + 1
        newer['trustedCertificates'] = []

        resolver.add_metadata(newer)

        cert = X509.load_cert_der_string(ATTESTATION_CERT)
        metadata = resolver.resolve(cert)

        assert metadata is None

    def test_versioning_older(self):
        resolver = create_resolver(YUBICO)
        newer = json.loads(json.dumps(YUBICO))
        newer['trustedCertificates'] = []

        resolver.add_metadata(newer)

        cert = X509.load_cert_der_string(ATTESTATION_CERT)
        metadata = resolver.resolve(cert)

        assert metadata.identifier == '2fb54029-7613-4f1d-94f1-fb876c14a6fe'
