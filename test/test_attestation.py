#    Copyright (C) 2014  Yubico AB
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

from u2flib_server.attestation.metadata import MetadataProvider
from u2flib_server.attestation.resolvers import create_resolver
from u2flib_server.attestation.data import YUBICO
from M2Crypto import X509
import json

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


def test_resolver():
    resolver = create_resolver(YUBICO)
    cert = X509.load_cert_der_string(ATTESTATION_CERT)

    metadata = resolver.resolve(cert)
    assert metadata.identifier == '2fb54029-7613-4f1d-94f1-fb876c14a6fe'


def test_provider():
    provider = MetadataProvider()
    cert = X509.load_cert_der_string(ATTESTATION_CERT)
    attestation = provider.get_attestation(cert)

    assert attestation.trusted


def test_versioning_newer():
    resolver = create_resolver(YUBICO)
    newer = json.loads(json.dumps(YUBICO))
    newer['version'] = newer['version'] + 1
    newer['trustedCertificates'] = []

    resolver.add_metadata(newer)

    cert = X509.load_cert_der_string(ATTESTATION_CERT)
    metadata = resolver.resolve(cert)

    assert metadata is None


def test_versioning_older():
    resolver = create_resolver(YUBICO)
    newer = json.loads(json.dumps(YUBICO))
    newer['trustedCertificates'] = []

    resolver.add_metadata(newer)

    cert = X509.load_cert_der_string(ATTESTATION_CERT)
    metadata = resolver.resolve(cert)

    assert metadata.identifier == '2fb54029-7613-4f1d-94f1-fb876c14a6fe'
