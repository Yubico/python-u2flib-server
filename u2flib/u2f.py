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
import json
import os
import struct

__all__ = ['U2FEnrollment', 'U2FBinding', 'U2FChallenge']

CURVE = EC.NID_X9_62_prime256v1
CIPHER = 'des_ede_cbc'
DEFAULT_IV = '\0' * 8
PEM_PRIVATE_KEY = """
-----BEGIN EC PRIVATE KEY-----
%s
-----END EC PRIVATE KEY-----
"""
PUB_KEY_DER_PREFIX = "3059301306072a8648ce3d020106082a8648ce3d030107034200" \
    .decode('hex')
SIZE_KQ = 32 * 2 + 1  # EC Point size
SIZE_HK = 64  # GN_WRAP_SIZE
SIZE_GRM = 384 + 72  # MAX_CERT + MAX_SIG


def b64_split(der):
    b64 = b64encode(der)
    return '\n'.join([b64[i:i + 64] for i in range(0, len(b64), 64)])


def P2DES(priv, pub):
    pub_raw = EC.pub_key_from_der(PUB_KEY_DER_PREFIX + urlsafe_b64decode(pub))
    return priv.compute_dh_key(pub_raw)[:16]


def H(data):
    h = sha256()
    h.update(data)
    return h.digest()


def update_all(cipher, from_buf, to_buf):
    while True:
        buf = from_buf.read()
        if not buf:
            break
        to_buf.write(cipher.update(buf))
    to_buf.write(cipher.final())
    return to_buf.getvalue()


def pad(data, blksize=8):
    padded = data + ('\0' * ((blksize - len(data)) % blksize))
    return padded


def encrypt(ptext, key, iv=DEFAULT_IV):
    cipher = EVP.Cipher(CIPHER, key, iv, 1, padding=0)
    padded = pad(ptext)
    result = update_all(cipher, StringIO(padded), StringIO())
    return result


def decrypt(ctext, key, iv=DEFAULT_IV):
    cipher = EVP.Cipher(CIPHER, key, iv, 0, padding=0)
    padded = pad(ctext)
    return update_all(cipher, StringIO(padded), StringIO())


class U2FEnrollment(object):
    def __init__(self, dh=None):
        if dh:
            if not isinstance(dh, EC.EC):
                raise TypeError('dh must be an instance of %s' % EC.EC)
            self.dh = dh
        else:
            self.dh = EC.gen_params(CURVE)
            self.dh.gen_key()
        der = str(self.dh.pub().get_der())
        self.ys = urlsafe_b64encode(der[-65:])

    def verify_csr_signature(self, cert, digest, signature):
        attest_key = EC.pub_key_from_der(encoder.encode(cert[0][6]))
        assert attest_key.verify_dsa_asn1(digest, signature), \
            'Attest signature verification failed!'

    def verify_cert(self, cert):
        # TODO: Validate attestation certificate
        pass

    def bind(self, response, origin):
        """
        response = {
            "version": "v0",
            "iv": "DOsdfoi2KD28",
            "grm": "32498DLFKEER243...",
            "dh": "BFJ2934FLKDFJ..."
        }
        """
        if isinstance(response, basestring):
            response = json.loads(response)
        assert response['version'].encode('utf-8') == 'v0'

        ho = H(origin.lower().encode('punycode'))

        if 'iv' in response:
            iv = urlsafe_b64decode(response['iv'].encode('utf-8'))
        else:
            iv = DEFAULT_IV
        km = P2DES(self.dh, response['dh'].encode('utf-8'))
        data = decrypt(urlsafe_b64decode(response['grm'].encode('utf-8')),
                       km, iv)

        kq = data[:SIZE_KQ]
        hk = data[SIZE_KQ:(SIZE_KQ + SIZE_HK)]
        grm = data[(SIZE_KQ + SIZE_HK):(SIZE_KQ + SIZE_HK + SIZE_GRM)]

        # Extract cert, public key:
        cert, signature = decoder.decode(grm)

        digest = H(ho + kq + hk)
        self.verify_csr_signature(cert, digest, signature)
        self.verify_cert(cert)

        kq = EC.pub_key_from_der(PUB_KEY_DER_PREFIX + kq)

        return U2FBinding(ho, kq, km, hk)

    @property
    def json(self):
        return json.dumps({'v0': self.ys})

    @property
    def der(self):
        bio = BIO.MemoryBuffer()
        self.dh.save_key_bio(bio, None)
        # Convert from PEM format
        der = b64decode(bio.read_all().splitlines()[1:-1])
        return der

    @classmethod
    def from_der(der):
        # Convert to PEM format
        pem = PEM_PRIVATE_KEY % b64_split(der)
        dh = EC.load_key_bio(BIO.MemoryBuffer(pem))
        return U2FEnrollment(dh)


class U2FBinding(object):
    def __init__(self, ho, kq, km, hk):
        self.ho = ho
        self.kq = kq
        self.km = km
        self.hk = hk

    def make_challenge(self):
        return U2FChallenge(self)

    @property
    def der(self):
        return ""

    @classmethod
    def from_der(der):
        return U2FBinding(None, None, None, None)


class U2FChallenge(object):
    def __init__(self, binding):
        self.binding = binding
        self.cpk = os.urandom(16)
        self.challenge = os.urandom(16)

    def validate_browser_data(self, browser_data):
        """
        browser_data = {
            "typ": "navigator.id.getAssertion",
            "cid_pubkey": { // channel id pubkey
                "alg": "EC",
                "crv": "P 256",
                "x": "DLFK4398374DKFDF...",
                "y": "DF3408DFLKjdfsdf..."
                },
                "server_pubkey": { // TLS server side pubkey
                    "alg": "RSA",
                    "mod": "LDKFJ3094...",
                    "exp": "AQAB"
                },
            "challenge": "JJ498DLFKEER243...", // from JS call parameter
        }
        """
        assert urlsafe_b64decode(browser_data['challenge'].encode('utf-8')) \
            == self.challenge
        # TODO: Assert more stuff

    def validate(self, response):
        """
        response = {
            "origin": "http://...",
            "browser_data": "3984dFSLDDFLJ...",
            "cpk": "LDFKJ38FDSKLF...",
            "counter": "3437467",
            "touch": "255",
            "signature": "293478LFJDFKJ..."
        }
        """
        if isinstance(response, basestring):
            response = json.loads(response)

        # This doesn't provide anything as both are verified in the signature.
        assert urlsafe_b64decode(response['cpk'].encode('utf-8')) == self.cpk
        assert H(response['origin'].encode('utf-8')) == self.binding.ho

        # Create hash for signature verification:
        browser_data = response['browser_data'].encode('utf-8')
        Hb = H(browser_data)
        touch = struct.pack('>B', (int(response['touch'])))
        counter = struct.pack('>I', int(response['counter']))

        digest = H(self.binding.ho + Hb + self.cpk + touch + counter)
        signature = urlsafe_b64decode(response['signature'].encode('utf-8'))
        assert self.binding.kq.verify_dsa_asn1(digest, signature), \
            "Signature verification failed!"

        self.validate_browser_data(json.loads(urlsafe_b64decode(browser_data)))

        return True

    @property
    def json(self):
        return json.dumps({
            'version': 'v0',
            'challenge': urlsafe_b64encode(self.challenge),
            'key_handle': urlsafe_b64encode(self.binding.hk),
            # cpk currently not used
            'cpk': {
                'clear': urlsafe_b64encode(self.cpk),
                'encrypted': urlsafe_b64encode(encrypt(self.cpk,
                                                       self.binding.km))
            }
        })

    @property
    def der(self):
        # TODO
        return ""

    @classmethod
    def from_der(der):
        # TODO
        return U2FChallenge(None)


def enrollment():
    return U2FEnrollment()


enrollment_from_der = U2FEnrollment.from_der
