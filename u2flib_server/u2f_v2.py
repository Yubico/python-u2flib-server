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

from u2flib_server.jsapi import (RegisterRequest, RegisterResponse,
                                 SignRequest, SignResponse, DeviceRegistration)
from u2flib_server.utils import (certificate_from_der, pub_key_from_der, sha_256, subject_from_certificate,
                                 websafe_decode, websafe_encode, rand_bytes,
                                 verify_ecdsa_signature)
from u2flib_server.yubicommon.compat import byte2int
import codecs
import struct

from cryptography.hazmat.primitives.serialization import Encoding


__all__ = [
    'start_register',
    'complete_register',
    'start_authenticate',
    'verify_authenticate'
]


VERSION = 'U2F_V2'

FIXSIG = [
    'CN=Yubico U2F EE Serial 776137165',
    'CN=Yubico U2F EE Serial 1086591525',
    'CN=Yubico U2F EE Serial 1973679733',
    'CN=Yubico U2F EE Serial 13503277888',
    'CN=Yubico U2F EE Serial 13831167861',
    'CN=Yubico U2F EE Serial 14803321578'
]


class RawRegistrationResponse(object):

    """
    Object representing a raw registration response.

    registrationData = 0x05, pubkey, kh_len, key_handle, cert, signature
    """
    PUBKEY_LEN = 65

    def __init__(self, app_param, chal_param, data):
        self.app_param = app_param
        self.chal_param = chal_param
        self.data = data

        if byte2int(data[0]) != 0x05:
            raise ValueError("Invalid data: %r" % (data,))

        data = data[1:]
        self.pub_key = data[:self.PUBKEY_LEN]

        data = data[self.PUBKEY_LEN:]

        kh_len = byte2int(data[0])
        data = data[1:]

        self.key_handle = data[:kh_len]
        data = data[kh_len:]

        self.certificate = self._fixsig(certificate_from_der(data))
        self.signature = data[len(self.certificate.public_bytes(Encoding.DER)):]

    def __str__(self):
        # N.B. Ensure this returns a str() on both Python 2 and Python 3
        hex_bytes = codecs.encode(self.data, 'hex_codec')
        hex_text = codecs.decode(hex_bytes, 'ascii')
        return str(hex_text)

    def verify_csr_signature(self):
        data = (b'\x00' + self.app_param + self.chal_param +
                self.key_handle + self.pub_key)
        digest = sha_256(data)
        pub_key = self.certificate.public_key()

        verify_ecdsa_signature(digest, pub_key, self.signature)

    def _fixsig(self, cert):
        subject = 'CN=' + subject_from_certificate(cert)

        if subject in FIXSIG:  # Set unused bits in signature to 0
            der = list(cert.public_bytes(Encoding.DER))
            der[-257] = b'\x00'
            cert = certificate_from_der(der)
        return cert

    def serialize(self):
        return websafe_encode(self.app_param + self.chal_param + self.data)

    @classmethod
    def deserialize(cls, serialized):
        data = websafe_decode(serialized)
        return cls(data[:32], data[32:64], data[64:])


class RawAuthenticationResponse(object):

    """
    Object representing a raw authentication response.

    authenticationData = touch, counter, signature
    """

    def __init__(self, app_param, chal_param, data):
        self.app_param = app_param
        self.chal_param = chal_param
        self.data = data

        self.user_presence = data[0:1]
        self.counter = data[1:5]
        self.counter_int = struct.unpack('>I', self.counter)[0]
        self.signature = data[5:]

    def __str__(self):
        # N.B. Ensure this returns a str() on both Python 2 and Python 3
        hex_bytes = codecs.encode(self.data, 'hex_codec')
        hex_text = codecs.decode(hex_bytes, 'ascii')
        return str(hex_text)

    def verify_signature(self, pubkey):
        data = (self.app_param + self.user_presence + self.counter +
                self.chal_param)
        digest = sha_256(data)
        pub_key = pub_key_from_der(pubkey)

        verify_ecdsa_signature(digest, pub_key, self.signature)

    def serialize(self):
        return websafe_encode(self.app_param + self.chal_param + self.data)

    @classmethod
    def deserialize(cls, serialized):
        data = websafe_decode(serialized)
        return cls(data[:32], data[32:64], data[64:])


def _validate_client_data(client_data, challenge, typ, valid_facets):
    """
    Validate the client data.

    clientData = {
        "typ": string,
        "challenge": string, //b64 encoded challenge.
        "origin": string, //Facet used
    }

    """
    if client_data.typ != typ:
        raise ValueError("Wrong type! Was: %r, expecting: %r" % (
            client_data.typ, typ))

    if challenge != client_data.challenge:
        raise ValueError("Wrong challenge! Was: %r, expecting: %r" % (
            client_data.challenge, challenge))

    if valid_facets is not None and client_data.origin not in valid_facets:
        raise ValueError("Invalid facet! Was: %r, expecting one of: %r" % (
            client_data.origin, valid_facets))


def start_register(app_id, challenge=None):
    if challenge is None:
        challenge = rand_bytes(32)

    return RegisterRequest(
        version=VERSION,
        appId=app_id,
        challenge=websafe_encode(challenge)
    )


def complete_register(request, response, valid_facets=None):
    request = RegisterRequest.wrap(request)
    response = RegisterResponse.wrap(response)

    _validate_client_data(response.clientData, request.challenge,
                          "navigator.id.finishEnrollment", valid_facets)

    raw_response = RawRegistrationResponse(
        request.appParam,
        response.clientParam,
        response.registrationData
    )

    raw_response.verify_csr_signature()

    return DeviceRegistration(
        appId=request.appId,
        keyHandle=websafe_encode(raw_response.key_handle),
        publicKey=websafe_encode(raw_response.pub_key)
    ), raw_response.certificate


def start_authenticate(device, challenge=None):
    device = DeviceRegistration.wrap(device)

    if challenge is None:
        challenge = rand_bytes(32)

    return SignRequest(
        version=VERSION,
        appId=device.appId,
        keyHandle=device.keyHandle,
        challenge=websafe_encode(challenge)
    )


def verify_authenticate(device, request, response, valid_facets=None):
    device = DeviceRegistration.wrap(device)
    request = SignRequest.wrap(request)
    response = SignResponse.wrap(response)

    _validate_client_data(response.clientData, request.challenge,
                          "navigator.id.getAssertion", valid_facets)

    raw_response = RawAuthenticationResponse(
        device.appParam,
        response.clientParam,
        response.signatureData
    )
    raw_response.verify_signature(websafe_decode(device.publicKey))

    return raw_response.counter_int, raw_response.user_presence
