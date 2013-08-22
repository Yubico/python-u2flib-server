# Copyright (C) 2013 Yubico AB.
# All rights reserved.
# Proprietary code owned by Yubico AB.
# No rights to modifications or redistribution.

from M2Crypto import EC, BIO
from base64 import urlsafe_b64encode, urlsafe_b64decode
from u2flib_server import u2f_v0 as u2f
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
        yd = urlsafe_b64encode(dh.pub().get_der()[-65:])
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
        cdata = urlsafe_b64encode(u2f.E(data, km))

        return json.dumps({
            "version": 'v0',
            "grm": cdata,
            "dh": yd
        })

    def getAssertionV0(self, params,
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
        hk = urlsafe_b64decode(params['key_handle'].encode('utf-8'))
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
        challenge = urlsafe_b64decode(params['challenge'].encode('utf-8'))

        digest = u2f.H(ho + touch + rnd + counter + challenge)
        signature = privu.sign_dsa_asn1(digest)

        enc = u2f.E(rnd + counter + signature, km)

        return json.dumps({
            "touch": str(touch_val),
            "enc": urlsafe_b64encode(enc)
        })

    def getAssertionV1(self, params, browser_data=None,
                       origin="https://www.example.com", touch=False):
        """
        params = {
            "key_handle": "PCbxwb-Al...",
            "challenge": "gaj0GUFl15...",
            "version": "v1",
            "cpk": {
                "encrypted": "iMDeGDDI...",
                "clear": "DZLX7FrEb..."
            }
        }
        """
        if isinstance(params, basestring):
            params = json.loads(params)

        if params['version'] != 'v1':
            raise ValueError("Unsupported version: %s" % params['version'])
        hk = urlsafe_b64decode(params['key_handle'].encode('utf-8'))
        if not hk in self.keys:
            raise ValueError("Unknown key handle!")

        # Unwrap:
        privu, km, ho = self.keys[hk]

        if browser_data is None:
            browser_data = {}
        if not 'typ' in browser_data:
            browser_data['typ'] = 'navigator.id.getAssertion'
        if not 'challenge' in browser_data:
            browser_data['challenge'] = params['challenge']
        self.counter += 1

        # Create signature
        browser_data = urlsafe_b64encode(json.dumps(browser_data))
        Hb = u2f.H(browser_data)
        cpk = urlsafe_b64decode(params['cpk']['clear'].encode('utf8'))
        touch_val = 255 if touch else 0
        touch = struct.pack('>B', touch_val)
        counter = struct.pack('>I', self.counter)

        digest = u2f.H(ho + Hb + cpk + touch + counter)
        signature = privu.sign_dsa_asn1(digest)

        return json.dumps({
            "origin": origin.lower().encode('punycode'),
            "browser_data": browser_data,
            "cpk": params['cpk']['clear'],
            "counter": str(self.counter),
            "touch": str(touch_val),
            "signature": urlsafe_b64encode(signature)
        })

    def getAssertion(self, params, *args, **kwargs):
        if isinstance(params, basestring):
            p = json.loads(params)
        else:
            p = params
        version = p['version']

        if version == 'v0':
            return self.getAssertionV0(params, *args, **kwargs)
        elif version == 'v1':
            return self.getAssertionV1(params, *args, **kwargs)
        else:
            raise ValueError('Unsupported version!')
