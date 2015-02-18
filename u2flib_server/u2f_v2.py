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

from M2Crypto import X509
from u2flib_server.jsapi import (RegisterRequest, RegisterResponse,
                                 SignRequest, SignResponse, DeviceRegistration)
from u2flib_server.utils import (pub_key_from_der, sha_256, websafe_decode,
                                 websafe_encode, rand_bytes)
import struct

__all__ = [
    'start_register',
    'complete_register',
    'start_authenticate',
    'verify_authenticate'
]


VERSION = 'U2F_V2'

FIXSIG = [
    'CN=Yubico U2F EE Serial 364846018',
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

        if ord(data[0]) != 0x05:
            raise ValueError("Invalid data: %s" % data.encode('hex'))

        data = data[1:]
        self.pub_key = data[:self.PUBKEY_LEN]
        data = data[self.PUBKEY_LEN:]

        kh_len = ord(data[0])
        data = data[1:]

        self.key_handle = data[:kh_len]
        data = data[kh_len:]

        self.certificate = self._fixsig(X509.load_cert_der_string(data))
        self.signature = data[len(self.certificate.as_der()):]

    def __str__(self):
        return self.data.encode('hex')

    def verify_csr_signature(self):
        data = chr(0x00) + self.app_param + self.chal_param + \
            self.key_handle + self.pub_key
        pubkey = self.certificate.get_pubkey()
        pubkey.reset_context('sha256')
        pubkey.verify_init()
        pubkey.verify_update(data)
        if not pubkey.verify_final(self.signature) == 1:
            raise Exception('Attestation signature verification failed!')

    def _fixsig(self, cert):
        subject = cert.get_subject().as_text()
        if subject in FIXSIG:  # Set unused bits in signature to 0
            der = list(cert.as_der())
            der[-257] = chr(0)
            cert = X509.load_cert_der_string(''.join(der))
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

        self.user_presence = data[0]
        self.counter = data[1:5]
        self.counter_int = struct.unpack('>I', self.counter)[0]
        self.signature = data[5:]

    def __str__(self):
        return self.data.encode('hex')

    def verify_signature(self, pubkey):
        data = self.app_param + self.user_presence + self.counter + \
            self.chal_param
        digest = sha_256(data)
        pub_key = pub_key_from_der(pubkey)
        if not pub_key.verify_dsa_asn1(digest, self.signature) == 1:
            raise Exception('Challenge signature verification failed!')

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
        raise ValueError("Wrong type! Was: %s, expecting: %s" % (
            client_data.typ, typ))

    if challenge != client_data.challenge:
        raise ValueError("Wrong challenge! Was: %s, expecting: %s" % (
            client_data.challenge.encode('hex'),
            challenge.encode('hex')))

    if valid_facets is not None and client_data.origin not in valid_facets:
        raise ValueError("Invalid facet! Was: %s, expecting one of: %r" % (
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
