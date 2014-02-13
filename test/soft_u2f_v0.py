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

from M2Crypto import EC, BIO
from u2flib_server import u2f_v0 as u2f
from u2flib_server.utils import websafe_encode, websafe_decode
import json
import os
import struct

CERT = """
MIIBhzCCAS6gAwIBAgIJAJm+6LEMouwcMAkGByqGSM49BAEwITEfMB0GA1UEAwwW
WXViaWNvIFUyRiBTb2Z0IERldmljZTAeFw0xMzA3MTcxNDIxMDNaFw0xNjA3MTYx
NDIxMDNaMCExHzAdBgNVBAMMFll1YmljbyBVMkYgU29mdCBEZXZpY2UwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAAQ74Zfdc36YPZ+w3gnnXEPIBl1J3pol6IviRAMc
/hCIZFbDDwMs4bSWeFdwqjGfjDlICArdmjMWnDF/XCGvHYEto1AwTjAdBgNVHQ4E
FgQUDai/k1dOImjupkubYxhOkoX3sZ4wHwYDVR0jBBgwFoAUDai/k1dOImjupkub
YxhOkoX3sZ4wDAYDVR0TBAUwAwEB/zAJBgcqhkjOPQQBA0gAMEUCIFyVmXW7zlnY
VWhuyCbZ+OKNtSpovBB7A5OHAH52dK9/AiEA+mT4tz5eJV8W2OwVxcq6ZIjrwqXc
jXSy2G0k27yAUDk=
""".decode('base64')
CERT_PRIV = """
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMyk3gKcDg5lsYdl48fZoIFORhAc9cQxmn2Whv/+ya+2oAoGCCqGSM49
AwEHoUQDQgAEO+GX3XN+mD2fsN4J51xDyAZdSd6aJeiL4kQDHP4QiGRWww8DLOG0
lnhXcKoxn4w5SAgK3ZozFpwxf1whrx2BLQ==
-----END EC PRIVATE KEY-----
"""


class SoftU2FDevice(object):

    """
    This simulates the U2F browser API with a soft U2F device connected.
    It can be used for testing.
    """
    def __init__(self):
        self.keys = {}
        self.counter = 0

    def register(self, keys, origin="https://www.example.com"):
        """
        keys = {
            "v1": "BPi7ppTCEi...", #b64 encoded DER encoded ys
            "v2": "..."
        }
        """
        if isinstance(keys, basestring):
            keys = json.loads(keys)

        if not 'v0' in keys:
            raise ValueError("Unsupported U2F version!")

        # DH key exchange
        ys = keys['v0'].encode('utf-8')
        dh = EC.gen_params(u2f.CURVE)
        dh.gen_key()
        yd = websafe_encode(dh.pub().get_der()[-65:])
        km = u2f.P2DES(dh, ys)

        # ECC key generation
        privu = EC.gen_params(u2f.CURVE)
        privu.gen_key()
        kq = str(privu.pub().get_der())[-65:]

        # Store
        hk = os.urandom(64)
        ho = u2f.H(origin.encode('idna'))
        self.keys[hk] = (privu, km, ho)

        # Attestation signature
        cert_priv = EC.load_key_bio(BIO.MemoryBuffer(CERT_PRIV))
        cert = CERT
        digest = u2f.H(ho + kq + hk)
        signature = cert_priv.sign_dsa_asn1(digest)

        data = kq + hk + cert + signature
        cdata = websafe_encode(u2f.E(data, km))

        return json.dumps({
            "version": 'v0',
            "grm": cdata,
            "dh": yd
        })

    def getAssertion(self, params,
                     origin="https://www.example.com", touch=False):
        """
        params = {
            "version": "v0",
            "key_handle": "PCbxwb-Al...",
            "challenge": "gaj0GUFl15...",
        }
        """
        if isinstance(params, basestring):
            params = json.loads(params)

        if params['version'] != 'v0':
            raise ValueError("Unsupported version: %s" % params['version'])
        hk = websafe_decode(params['key_handle'].encode('utf-8'))
        if not hk in self.keys:
            raise ValueError("Unknown key handle!")

        # Unwrap:
        privu, km, ho = self.keys[hk]

        self.counter += 1

        # Create signature
        touch_val = 255 if touch else 0
        touch = struct.pack('>B', touch_val)
        counter = struct.pack('>I', self.counter)
        rnd = os.urandom(4)
        challenge = websafe_decode(params['challenge'].encode('utf-8'))

        digest = u2f.H(ho + touch + rnd + counter + challenge)
        signature = privu.sign_dsa_asn1(digest)

        enc = u2f.E(rnd + counter + signature, km)

        return json.dumps({
            "touch": str(touch_val),
            "enc": websafe_encode(enc)
        })
