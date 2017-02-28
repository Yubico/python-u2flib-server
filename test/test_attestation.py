from u2flib_server.model import Transport
from u2flib_server.attestation.metadata import MetadataProvider
from u2flib_server.attestation.resolvers import create_resolver
from u2flib_server.attestation.data import YUBICO
from u2flib_server.attestation.model import (
    VendorInfo, Selector,
    DeviceInfo, MetadataObject
)
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from base64 import b64decode
import json
import unittest

ATTESTATION_CERT = b64decode(b"""
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
""")


ATTESTATION_CERT_WITH_TRANSPORT = b64decode(b"""
MIICIjCCAQygAwIBAgIEIHHwozALBgkqhkiG9w0BAQswDzENMAsGA1UEAxMEdGVz
dDAeFw0xNTA4MTEwOTAwMzNaFw0xNjA4MTAwOTAwMzNaMCkxJzAlBgNVBAMTHll1
YmljbyBVMkYgRUUgU2VyaWFsIDU0NDMzODA4MzBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABPdFG1pBjBBQVhLrD39Qg1vKjuR2kRdBZnwLI/zgzztQpf4ffpkrkB/3
E0TXj5zg8gN9sgMkX48geBe+tBEpvMmjOzA5MCIGCSsGAQQBgsQKAgQVMS4zLjYu
MS40LjEuNDE0ODIuMS4yMBMGCysGAQQBguUcAgEBBAQDAgQwMAsGCSqGSIb3DQEB
CwOCAQEAb3YpnmHHduNuWEXlLqlnww9034ZeZaojhPAYSLR8d5NPk9gc0hkjQKmI
aaBM7DsaHbcHMKpXoMGTQSC++NCZTcKvZ0Lt12mp5HRnM1NNBPol8Hte5fLmvW4t
Q9EzLl4gkz7LSlORxTuwTbae1eQqNdxdeB+0ilMFCEUc+3NGCNM0RWd+sP5+gzMX
BDQAI1Sc9XaPIg8t3du5JChAl1ifpu/uERZ2WQgtxeBDO6z1Xoa5qz4svf5oURjP
ZjxS0WUKht48Z2rIjk5lZzERSaY3RrX3UtrnZEIzCmInXOrcRPeAD4ZutpiwuHe6
2ABsjuMRnKbATbOUiLdknNyPYYQz2g==
""")


YUBICO_RESOLVER = create_resolver(YUBICO)
EMPTY_RESOLVER = create_resolver([])


class AttestationTest(unittest.TestCase):

    def test_resolver(self):
        metadata = YUBICO_RESOLVER.resolve(ATTESTATION_CERT)
        self.assertEqual(metadata.identifier,
                         '2fb54029-7613-4f1d-94f1-fb876c14a6fe')

    def test_provider(self):
        provider = MetadataProvider(YUBICO_RESOLVER)
        attestation = provider.get_attestation(ATTESTATION_CERT)

        self.assertTrue(attestation.trusted)

    def test_versioning_newer(self):
        resolver = create_resolver(YUBICO)
        newer = json.loads(json.dumps(YUBICO))
        newer['version'] = newer['version'] + 1
        newer['trustedCertificates'] = []

        resolver.add_metadata(newer)

        metadata = resolver.resolve(ATTESTATION_CERT)

        self.assertIsNone(metadata)

    def test_versioning_older(self):
        resolver = create_resolver(YUBICO)
        newer = json.loads(json.dumps(YUBICO))
        newer['trustedCertificates'] = []

        resolver.add_metadata(newer)

        metadata = resolver.resolve(ATTESTATION_CERT)

        self.assertEqual(metadata.identifier,
                         '2fb54029-7613-4f1d-94f1-fb876c14a6fe')

    def test_transports_from_cert(self):
        provider = MetadataProvider(EMPTY_RESOLVER)
        attestation = provider.get_attestation(ATTESTATION_CERT_WITH_TRANSPORT)

        self.assertSetEqual(set(attestation.transports),
                            set([Transport.USB, Transport.NFC]))

    def test_transports_from_metadata(self):
        provider = MetadataProvider(YUBICO_RESOLVER)
        cert = x509.load_der_x509_certificate(ATTESTATION_CERT,
                                              default_backend())
        attestation = provider.get_attestation(cert)
        self.assertEqual(attestation.transports, [Transport.USB])


class DeviceInfoTest(unittest.TestCase):
    def test_selectors_empty(self):
        self.assertTrue(DeviceInfo().selectors is None)

    def test_selectors(self):
        devinfo = DeviceInfo(selectors=[{}, {'a': 1}, {'a': 1, 'b': 2}])
        self.assertEqual([{}, {'a': 1}, {'a': 1, 'b': 2}], devinfo.selectors)
        self.assertTrue(isinstance(devinfo.selectors[0], Selector))
        self.assertTrue(isinstance(devinfo.selectors[1], Selector))
        self.assertTrue(isinstance(devinfo.selectors[2], Selector))


class MetadataObjectTest(unittest.TestCase):
    def test_vendorinfo(self):
        metadata = MetadataObject(vendorInfo={})
        self.assertEqual({}, metadata.vendorInfo)
        self.assertTrue(isinstance(metadata.vendorInfo, VendorInfo))

    def test_devices(self):
        metadata = MetadataObject(devices=[{}, {'a': 1}, {'a': 1, 'b': 2}])
        self.assertEqual([{}, {'a': 1}, {'a': 1, 'b': 2}], metadata.devices)
        self.assertTrue(isinstance(metadata.devices[0], DeviceInfo))
        self.assertTrue(isinstance(metadata.devices[1], DeviceInfo))
        self.assertTrue(isinstance(metadata.devices[2], DeviceInfo))
