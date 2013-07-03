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
from base64 import urlsafe_b64encode, urlsafe_b64decode, b64decode
from pyasn1.codec.der import decoder, encoder
from u2flib import u2f_v1 as V1
from u2flib.utils import b64_split, pub_key_from_der
import json
import os
import struct

__all__ = ['U2FEnrollment', 'U2FBinding', 'U2FChallenge']

VERSION = 'v0'
CURVE = V1.CURVE
CIPHER = V1.CIPHER
H = V1.H
E = V1.E
D = V1.D
PEM_PRIVATE_KEY = """
-----BEGIN EC PRIVATE KEY-----
%s
-----END EC PRIVATE KEY-----
"""


def P2DES(priv, pub):
    # P2DES for v0 uses the least significant bytes, whereas v1 uses the most
    # significant bytes!
    pub_raw = pub_key_from_der(urlsafe_b64decode(pub))
    return priv.compute_dh_key(pub_raw)[-16:]


class GRM(object):
    """
    A "fake" GRM used in version 0
    """
    SIZE_KQ = 32 * 2 + 1  # EC Point size
    SIZE_HK = 64  # GN_WRAP_SIZE
    SIZE_GRM = 384 + 72  # MAX_CERT + MAX_SIG

    def __init__(self, data, ho):
        self.data = data
        self.ho = ho
        self.kq_der = data[:self.SIZE_KQ]
        self.kq = pub_key_from_der(self.kq_der)
        self.hk = data[self.SIZE_KQ:(self.SIZE_KQ + self.SIZE_HK)]
        rest = data[(self.SIZE_KQ + self.SIZE_HK):(
            self.SIZE_KQ + self.SIZE_HK + self.SIZE_GRM)]
        self.csr, self.signature = decoder.decode(rest)

    def verify_csr_signature(self):
        digest = H(chr(2) + self.ho + self.kq_der + self.hk)
        attest_key = EC.pub_key_from_der(encoder.encode(self.csr[0][6]))
        if not attest_key.verify_dsa_asn1(digest, self.signature):
            raise Exception('Attest signature verification failed!')

    @property
    def der(self):
        return self.ho + self.data

    @staticmethod
    def from_der(der):
        return GRM(der[32:], der[:32])


class U2FEnrollment(object):
    def __init__(self, origin, dh=None, origin_as_hash=False):
        if origin_as_hash:
            self.ho = origin
        else:
            self.ho = H(origin.lower().encode('punycode'))

        if dh:
            if not isinstance(dh, EC.EC):
                raise TypeError('dh must be an instance of %s' % EC.EC)
            self.dh = dh
        else:
            self.dh = EC.gen_params(CURVE)
            self.dh.gen_key()
        der = str(self.dh.pub().get_der())
        self.ys = urlsafe_b64encode(der[-65:])

    def bind(self, response):
        """
        response = {
            "version": VERSION,
            "grm": "32498DLFKEER243...",
            "dh": "BFJ2934FLKDFJ..."
        }
        """
        if isinstance(response, basestring):
            response = json.loads(response)
        if response['version'].encode('utf-8') != VERSION:
            raise ValueError("Incorrect version: %s" % response['version'])

        km = P2DES(self.dh, response['dh'].encode('utf-8'))
        grm = GRM(D(urlsafe_b64decode(response['grm'].encode('utf-8')),
                    km), self.ho)

        # TODO: Make sure verify_csr_signature works.
        # grm.verify_csr_signature()
        # TODO: Validate the certificate as well

        return U2FBinding(grm, km)

    @property
    def json(self):
        return json.dumps({VERSION: self.ys})

    @property
    def der(self):
        bio = BIO.MemoryBuffer()
        self.dh.save_key_bio(bio, None)
        # Convert from PEM format
        der = b64decode(''.join(bio.read_all().splitlines()[1:-1]))
        return self.ho + der

    @staticmethod
    def from_der(der):
        # Convert to PEM format
        ho = der[:32]
        pem = PEM_PRIVATE_KEY % b64_split(der[32:])
        dh = EC.load_key_bio(BIO.MemoryBuffer(pem))
        return U2FEnrollment(ho, dh, origin_as_hash=True)


class U2FBinding(object):
    def __init__(self, grm, km):
        self.ho = grm.ho
        self.kq = grm.kq
        self.km = km
        self.hk = grm.hk
        # Not required, but useful:
        self.grm = grm

    def make_challenge(self):
        return U2FChallenge(self)

    def challenge_from_der(self, der):
        return U2FChallenge.from_der(self, der)

    @property
    def der(self):
        # Not actually DER, but it will do for v0.
        return self.km + self.grm.der

    @staticmethod
    def from_der(der):
        # Again, not actually DER
        return U2FBinding(GRM.from_der(der[16:]), der[:16])


class U2FChallenge(object):
    def __init__(self, binding, challenge=None):
        self.binding = binding
        if challenge is None:
            self.challenge = os.urandom(32)
        else:
            self.challenge = challenge

    def validate(self, response):
        """
        response = {
            "touch": "255",
            "enc": "ADJKSDFS..." #rnd, ctr, sig
        }
        """
        if isinstance(response, basestring):
            response = json.loads(response)

        # Decrypt response data
        data = D(urlsafe_b64decode(response['enc'].encode('utf-8')),
                 self.binding.km)
        rnd = data[:4]
        ctr = data[4:8]
        signature = data[8:]

        # Create hash for signature verification:
        touch_int = int(response['touch'])
        touch = struct.pack('>B', touch_int)
        counter_int = struct.unpack('>I', ctr)[0]

        digest = H(self.binding.ho + touch + rnd + ctr + self.challenge)

        if not self.binding.kq.verify_dsa_asn1(digest, signature):
            raise Exception("Signature verification failed!")

        return counter_int, touch_int

    @property
    def json(self):
        return json.dumps({
            'version': VERSION,
            'challenge': urlsafe_b64encode(self.challenge),
            'key_handle': urlsafe_b64encode(self.binding.hk),
        })

    @property
    def der(self):
        # Not actually DER, but it will do for v0.
        return self.challenge

    @staticmethod
    def from_der(binding, der):
        # Again, not actually DER
        return U2FChallenge(binding, der)


enrollment = U2FEnrollment.__call__
enrollment_from_der = U2FEnrollment.from_der
binding_from_der = U2FBinding.from_der
