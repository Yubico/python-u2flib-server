# Copyright (C) 2013 Yubico AB.
# All rights reserved.
# Proprietary code owned by Yubico AB.
# No rights to modifications or redistribution.

from M2Crypto import EC, BIO, EVP
from base64 import urlsafe_b64encode, urlsafe_b64decode, b64decode
from hashlib import sha256
from cStringIO import StringIO
from u2flib_server import GRM
from u2flib_server.utils import update_all, zeropad, pub_key_from_der, b64_split
import json
import os
import struct

__all__ = ['U2FEnrollment', 'U2FBinding', 'U2FChallenge']

VERSION = 'v1'
CURVE = EC.NID_X9_62_prime256v1
CIPHER = 'des_ede_cbc'
DEFAULT_IV = '\0' * 8
PEM_PRIVATE_KEY = """
-----BEGIN EC PRIVATE KEY-----
%s
-----END EC PRIVATE KEY-----
"""


def P2DES(priv, pub):
    pub_raw = pub_key_from_der(urlsafe_b64decode(pub))
    return priv.compute_dh_key(pub_raw)[:16]


def H(data):
    h = sha256()
    h.update(data)
    return h.digest()


def E(ptext, key, iv=DEFAULT_IV):
    cipher = EVP.Cipher(CIPHER, key, iv, 1, padding=0)
    padded = zeropad(ptext)
    result = update_all(cipher, StringIO(padded), StringIO())
    return result


def D(ctext, key, iv=DEFAULT_IV):
    cipher = EVP.Cipher(CIPHER, key, iv, 0, padding=0)
    padded = zeropad(ctext)
    return update_all(cipher, StringIO(padded), StringIO())


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
        self.ys = urlsafe_b64encode(der[-65:])

    def bind(self, response):
        """
        response = {
            "version": VERSION,
            "iv": "DOsdfoi2KD28",
            "grm": "32498DLFKEER243...",
            "dh": "BFJ2934FLKDFJ..."
        }
        """
        if isinstance(response, basestring):
            response = json.loads(response)
        if response['version'].encode('utf-8') != VERSION:
            raise ValueError("Incorrect version: %s", response['version'])

        iv = urlsafe_b64decode(response['iv'].encode('utf-8'))
        km = P2DES(self.dh, response['dh'].encode('utf-8'))
        grm = GRM(D(urlsafe_b64decode(response['grm'].encode('utf-8')),
                    km, iv))

        grm.verify_csr_signature()
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
        der = b64decode(bio.read_all().splitlines()[1:-1])
        return der

    @classmethod
    def from_der(der):
        # Convert to PEM format
        pem = PEM_PRIVATE_KEY % b64_split(der)
        dh = EC.load_key_bio(BIO.MemoryBuffer(pem))
        return U2FEnrollment(dh)


class U2FBinding(object):
    def __init__(self, grm, km):
        self.grm = grm
        self.km = km
        self.ho = grm.ho
        self.kq = grm.kq
        self.hk = grm.hk

    def make_challenge(self):
        return U2FChallenge(self)

    @property
    def der(self):
        return ""

    @classmethod
    def from_der(der):
        return U2FBinding(None, None)


class U2FChallenge(object):
    def __init__(self, binding):
        self.binding = binding
        self.cpk = os.urandom(16)
        self.challenge = os.urandom(32)

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
        if browser_data['typ'] != "navigator.id.getAssertion":
            raise Exception("Incorrect type!")
        if urlsafe_b64decode(browser_data['challenge'].encode('utf-8')) \
                != self.challenge:
            raise Exception("Incorrect challenge!")

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
        if urlsafe_b64decode(response['cpk'].encode('utf-8')) != self.cpk:
            raise Exception("Invalid cpk!")
        if H(response['origin'].encode('utf-8')) != self.binding.ho:
            raise Exception("Invalid origin!")

        # Create hash for signature verification:
        browser_data = response['browser_data'].encode('utf-8')
        Hb = H(browser_data)
        touch_int = int(response['touch'])
        touch = struct.pack('>B', touch_int)
        counter_int = int(response['counter'])
        counter = struct.pack('>I', counter_int)

        digest = H(self.binding.ho + Hb + self.cpk + touch + counter)
        signature = urlsafe_b64decode(response['signature'].encode('utf-8'))
        if not self.binding.kq.verify_dsa_asn1(digest, signature):
            raise Exception("Signature verification failed!")

        browser_data = json.loads(urlsafe_b64decode(browser_data))
        self.validate_browser_data(browser_data)

        return browser_data, counter_int, touch_int

    @property
    def json(self):
        return json.dumps({
            'version': VERSION,
            'challenge': urlsafe_b64encode(self.challenge),
            'key_handle': urlsafe_b64encode(self.binding.hk),
            'cpk': {
                'clear': urlsafe_b64encode(self.cpk),
                'encrypted': urlsafe_b64encode(E(self.cpk,
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


enrollment = U2FEnrollment.__call__
enrollment_from_der = U2FEnrollment.from_der
binding_from_der = U2FBinding.from_der
