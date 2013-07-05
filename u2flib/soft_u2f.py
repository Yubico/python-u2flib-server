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

from M2Crypto import EC, BIO
from base64 import urlsafe_b64encode, urlsafe_b64decode
from u2flib import u2f_v0 as u2f
import json
import os
import struct

# This is a modified cert using the private key below, its signature is
# incorrect. TODO: Fix this.
CERT = urlsafe_b64decode(
    "MIIBRDCB6qADAgECAgkBkYn_____UYMwCgYIKoZIzj0EAwIwGzEZMBcGA1UEAxMQR251Ym" +
    "J5IEhTTSBDQSAwMDAiGA8yMDEyMDYwMTAwMDAwMFoYDzIwNjIwNTMxMjM1OTU5WjAwMRkw" +
    "FwYDVQQDExBHb29nbGUgR251YmJ5IHYwMRMwEQYDVQQtAwoAAZGJ_____1GDMFkwEwYHKo" +
    "ZIzj0CAQYIKoZIzj0DAQcDQgAEKe7yqvUpDUbU2-DkutjIVtuXt9wvSftfhXrOS3uViksU" +
    "lShw9xhDs5nPludXT_J4SmtvXW92lsuQ_hQi3Z8hhzAKBggqhkjOPQQDAgNJADBGAiEAtM" +
    "rqXcYPv58ATthPxPGFIpgcHDAxVcCCdOiJ8_EMWyMCIQD6r7TxC5L0dU47CLWvNT94SFvJ" +
    "A-zn6pESZPwWc7ZZjw=="
)
CERT_PRIV = """
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMNV9aZZu95+h0EM2KH3aA42VrvuEk4aEBJMeKbX0l77oAoGCCqGSM49
AwEHoUQDQgAEKe7yqvUpDUbU2+DkutjIVtuXt9wvSftfhXrOS3uViksUlShw9xhD
s5nPludXT/J4SmtvXW92lsuQ/hQi3Z8hhw==
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
