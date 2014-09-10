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

from M2Crypto import EC, BIO, X509, EVP
from base64 import b64decode
from u2flib_server.utils import (update_all, zeropad, pub_key_from_der,
                                 sha_256, b64_split, websafe_encode,
                                 websafe_decode)
from cStringIO import StringIO
import json
import os
import struct

__all__ = ['U2FEnrollment', 'U2FBinding', 'U2FChallenge']

VERSION = 'v0'
CURVE = EC.NID_X9_62_prime256v1
CIPHER = 'des_ede_cbc'
DEFAULT_IV = '\0' * 8
PEM_PRIVATE_KEY = """
-----BEGIN EC PRIVATE KEY-----
%s
-----END EC PRIVATE KEY-----
"""


H = sha_256


def E(ptext, key, iv=DEFAULT_IV):
    cipher = EVP.Cipher(CIPHER, key, iv, 1, padding=0)
    padded = zeropad(ptext)
    result = update_all(cipher, StringIO(padded), StringIO())
    return result


def D(ctext, key, iv=DEFAULT_IV):
    cipher = EVP.Cipher(CIPHER, key, iv, 0, padding=0)
    padded = zeropad(ctext)
    return update_all(cipher, StringIO(padded), StringIO())


def P2DES(priv, pub):
    # P2DES for v0 uses the least significant bytes!
    pub_raw = pub_key_from_der(websafe_decode(pub))
    return priv.compute_dh_key(pub_raw)[-16:]


class GRM(object):
    """
    A "fake" GRM used in version 0
    """
    SIZE_KQ = 32 * 2 + 1  # EC Point size
    SIZE_HK = 64  # GN_WRAP_SIZE

    def __init__(self, data, ho):
        self.data = data
        self.ho = ho
        self.kq_der = data[:self.SIZE_KQ]
        self.kq = pub_key_from_der(self.kq_der)
        self.hk = data[self.SIZE_KQ:(self.SIZE_KQ + self.SIZE_HK)]
        rest = data[(self.SIZE_KQ + self.SIZE_HK):]
        self.att_cert = X509.load_cert_der_string(rest)
        self.signature = rest[len(self.att_cert.as_der()):]

    def verify_csr_signature(self):
        pubkey = self.att_cert.get_pubkey()
        #TODO: Figure out how to do this using the EVP API.
        #pubkey.verify_init()
        #pubkey.verify_update(self.ho + self.kq_der + self.hk)
        #if not pubkey.verify_final(self.signature) == 1:
        digest = H(self.ho + self.kq_der + self.hk)
        pub_key = EC.pub_key_from_der(pubkey.as_der())
        if not pub_key.verify_dsa_asn1(digest, self.signature) == 1:
            raise Exception('Attest signature verification failed!')

    def serialize(self):
        return self.ho + self.data

    @classmethod
    def deserialize(cls, der):
        return cls(der[32:], der[:32])


class U2FEnrollment(object):
    def __init__(self, origin, dh=None, origin_as_hash=False):
        if origin_as_hash:
            self.ho = origin
        else:
            self.ho = H(origin.encode('idna'))

        if dh:
            if not isinstance(dh, EC.EC):
                raise TypeError('dh must be an instance of %s' % EC.EC)
            self.dh = dh
        else:
            self.dh = EC.gen_params(CURVE)
            self.dh.gen_key()
        der = str(self.dh.pub().get_der())
        self.ys = websafe_encode(der[-65:])

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

        km = P2DES(self.dh, response['dh'])
        grm = GRM(D(websafe_decode(response['grm']),
                    km), self.ho)

        # TODO: Make sure verify_csr_signature works.
        grm.verify_csr_signature()
        # TODO: Validate the certificate as well

        return U2FBinding(grm, km)

    @property
    def json(self):
        return json.dumps({VERSION: self.ys})

    def serialize(self):
        bio = BIO.MemoryBuffer()
        self.dh.save_key_bio(bio, None)
        # Convert from PEM format
        der = b64decode(''.join(bio.read_all().splitlines()[1:-1]))
        return self.ho + der

    @classmethod
    def deserialize(cls, der):
        # Convert to PEM format
        ho = der[:32]
        pem = PEM_PRIVATE_KEY % b64_split(der[32:])
        dh = EC.load_key_bio(BIO.MemoryBuffer(pem))
        return cls(ho, dh, origin_as_hash=True)


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

    def deserialize_challenge(self, der):
        return U2FChallenge.deserialize(self, der)

    def serialize(self):
        # Not actually DER, but it will do for v0.
        return self.km + self.grm.serialize()

    @classmethod
    def deserialize(cls, der):
        # Again, not actually DER
        return cls(GRM.deserialize(der[16:]), der[:16])


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
            "enc": "ADJKSDFS...", #rnd, ctr, sig
            "bd": "SJDFSF..." #optional, browser data
        }
        """
        if isinstance(response, basestring):
            response = json.loads(response)

        # Decrypt response data
        data = D(websafe_decode(response['enc']),
                 self.binding.km)
        rnd = data[:4]
        ctr = data[4:8]
        signature = data[8:]

        # Create hash for signature verification:
        touch_int = int(response['touch'])
        touch = struct.pack('>B', touch_int)
        counter_int = struct.unpack('>I', ctr)[0]

        #If browser data was sent the challenge is the hash of it
        challenge = self.challenge
        if 'bd' in response:
            bd = websafe_decode(response['bd'])
            browser_data = json.loads(bd)
            # TODO verify more contents of browser_data
            bdc = websafe_decode(browser_data['challenge'])
            if bdc != self.challenge:
                raise Exception("Browser data contains wrong challenge!")
            challenge = H(bd)

        digest = H(self.binding.ho + touch + rnd + ctr + challenge)

        if not self.binding.kq.verify_dsa_asn1(digest, signature):
            raise Exception("Signature verification failed!")

        return counter_int, touch_int

    @property
    def json(self):
        return json.dumps({
            'version': VERSION,
            'challenge': websafe_encode(self.challenge),
            'key_handle': websafe_encode(self.binding.hk),
        })

    def serialize(self):
        # Not actually DER, but it will do for v0.
        return self.challenge

    @classmethod
    def deserialize(cls, binding, der):
        # Again, not actually DER
        return cls(binding, der)


enrollment = U2FEnrollment.__call__
deserialize_enrollment = U2FEnrollment.deserialize
deserialize_binding = U2FBinding.deserialize
