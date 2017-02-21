import unittest

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from u2flib_server.attestation.matchers import _get_ext_by_oid

YUBICO_ATTESTATION_CERT_SERIAL_544338083 = b'''-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----'''

# From https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers
# Regsitered number     Enterprise
# 1.3.6.1.4.1.41482     Yubico
# 1.3.6.1.4.1.45724     FIDO Alliance, Inc.


class X509ExtensionsTest(unittest.TestCase):

    attestation_cert = x509.load_pem_x509_certificate(
        YUBICO_ATTESTATION_CERT_SERIAL_544338083,
        default_backend(),
    )

    def test_get_ext_by_oid_yubico(self):
        self.assertEqual(
            b'1.3.6.1.4.1.41482.1.2',
            _get_ext_by_oid(self.attestation_cert, '1.3.6.1.4.1.41482.2'),
        )

    def test_get_ext_by_oid_fido_alliance(self):
        self.assertEqual(
            b'\x03\x02\x040',
            _get_ext_by_oid(self.attestation_cert, '1.3.6.1.4.1.45724.2.1.1'),
        )
