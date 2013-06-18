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

from M2Crypto import EC, BIO, EVP
from base64 import urlsafe_b64encode, urlsafe_b64decode, b64decode, b64encode
from hashlib import sha256
from cStringIO import StringIO
from pyasn1.codec.der import decoder, encoder
from u2flib import u2f
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

        assert 'v0' in keys, "Unsupported U2F version!"

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
        ho = u2f.H(origin.lower().encode('punycode'))
        self.keys[hk] = (privu, km, ho)

        # Attestation signature
        cert_priv = EC.load_key_bio(BIO.MemoryBuffer(CERT_PRIV))
        cert = CERT
        digest = u2f.H(ho + kq + hk)
        signature = cert_priv.sign_dsa_asn1(digest)

        data = kq + hk + cert + signature
        cdata = urlsafe_b64encode(u2f.encrypt(data, km))

        return {
            "version": 'v0',
            "grm": cdata,
            "dh": yd
        }

    def getAssertion(self, params, browser_data={},
                     origin="https://www.example.com"):
        """
        params = {
            "key_handle": "PCbxwb-Al...",
            "challenge": "gaj0GUFl15...",
            "version": "v0",
            "cpk": {
                "encrypted": "iMDeGDDI...",
                "clear": "DZLX7FrEb..."
            }
        }
        """
        if isinstance(params, basestring):
            params = json.loads(params)

        assert params['version'] == 'v0', "Unsupported version!"
        hk = urlsafe_b64decode(params['key_handle'])
        assert hk in self.keys, "Unknown key handle!"

        # Unwrap:
        privu, km, ho = self.keys[hk]

        browser_data['challenge'] = params['challenge']
        self.counter += 1

        signature = None

        return {
            "origin": origin.lower().encode('punycode'),
            "browser_data": urlsafe_b64encode(json.dumps(browser_data)),
            "cpk": params['cpk']['clear'],
            "counter": str(self.counter),
            "touch": "255",
            "signature": urlsafe_b64encode(signature)
        }
