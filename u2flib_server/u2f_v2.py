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

from M2Crypto import EC, X509
from u2flib_server.jsapi import (RegisterRequest, RegisterResponse,
                                 SignRequest, SignResponse)
from u2flib_server.utils import (pub_key_from_der, sha_256, websafe_decode,
                                 websafe_encode)
import json
import os
import struct

__all__ = ['U2FEnrollment', 'U2FBinding', 'U2FChallenge']

H = sha_256

VERSION = 'U2F_V2'


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

        self.certificate = X509.load_cert_der_string(data)
        self.signature = data[len(self.certificate.as_der()):]

    def __str__(self):
        return self.data.encode('hex')

    def verify_csr_signature(self):
        data = chr(0x00) + self.app_param + self.chal_param + \
            self.key_handle + self.pub_key
        pubkey = self.certificate.get_pubkey()
        # TODO: Figure out how to do this using the EVP API.
        # pubkey.verify_init()
        # pubkey.verify_update(data)
        # if not pubkey.verify_final(self.signature) == 1:
        digest = H(data)
        pub_key = EC.pub_key_from_der(pubkey.as_der())
        if not pub_key.verify_dsa_asn1(digest, self.signature) == 1:
            raise Exception('Attestation signature verification failed!')

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
        digest = H(data)
        pub_key = pub_key_from_der(pubkey)
        if not pub_key.verify_dsa_asn1(digest, self.signature) == 1:
            raise Exception('Challenge signature verification failed!')

    def serialize(self):
        return websafe_encode(self.app_param + self.chal_param + self.data)

    @classmethod
    def deserialize(cls, serialized):
        data = websafe_decode(serialized)
        return cls(data[:32], data[32:64], data[64:])


class U2FEnrollment(object):

    """
    A U2F enrollment object representing an incompleted registration.

    registrationData = {
        "version": "U2F_V2",
        "challenge": string //b64 encoded challenge, 32 bytes?
        "appId": string //A URL pointing to a list of approved facets.
    }

    """

    TYPE_FINISH_ENROLLMENT = "navigator.id.finishEnrollment"

    def __init__(self, app_id, facets=None, challenge=None):
        self.app_id = app_id
        self.app_param = H(app_id.encode('idna'))

        if facets is None:
            self.facets = []
        else:
            self.facets = facets

        if challenge is None:
            self.challenge = os.urandom(32)
        else:
            self.challenge = challenge

    def _validate_client_data(self, client_data):
        """
        Validate the client data.

        clientData = {
            "typ": TYPE_FINISH_ENROLLMENT,
            "challenge": string, //b64 encoded challenge.
            "origin": string, //Facet used
        }

        """
        if client_data.typ != self.TYPE_FINISH_ENROLLMENT:
            raise ValueError("Wrong type! Was: %s, expecting: %s" % (
                client_data.typ, self.TYPE_FINISH_ENROLLMENT))

        if self.challenge != client_data.challenge:
            raise ValueError("Wrong challenge! Was: %s, expecting: %s" % (
                client_data.challenge.encode('hex'),
                self.challenge.encode('hex')))

        if client_data.origin not in self.facets:
            raise ValueError("Invalid facet! Was: %s, expecting one of: %r" % (
                client_data.origin, self.facets))

    def bind(self, response):
        """
        Complete registration, returning a U2FBinding.

        registrationResponse = {
            "registrationData": string, //b64 encoded raw registration response
            "clientData": string, //b64 encoded JSON of ClientData
        }

        """
        if not isinstance(response, RegisterResponse):
            response = RegisterResponse(response)

        self._validate_client_data(response.clientData)

        raw_response = RawRegistrationResponse(
            self.app_param,
            response.clientParam,
            websafe_decode(response['registrationData'])
        )

        raw_response.verify_csr_signature()
        # TODO: Validate the certificate as well

        return U2FBinding(self.app_id, self.facets, raw_response)

    @property
    def data(self):
        """Return a RegisterRequest object."""
        return RegisterRequest({
            'version': VERSION,
            'challenge': websafe_encode(self.challenge),
            'appId': self.app_id
        })

    @property
    def json(self):
        """Return a JSON RegisterRequest object to be sent to the client."""
        return self.data.json

    def serialize(self):
        return json.dumps({
            'appId': self.app_id,
            'facets': self.facets,
            'challenge': websafe_encode(self.challenge)
        })

    @classmethod
    def deserialize(cls, serialized):
        data = json.loads(serialized)
        return cls(data['appId'], data['facets'],
                   websafe_decode(data['challenge']))


class U2FBinding(object):

    """A U2F binding object representing a completed registration."""

    def __init__(self, app_id, facets, response):
        self.app_id = app_id
        self.facets = facets
        self.pub_key = response.pub_key
        self.key_handle = response.key_handle
        self.certificate = response.certificate
        self.response = response

    def make_challenge(self, challenge=None):
        return U2FChallenge(self, challenge)

    def deserialize_challenge(self, serialized):
        return U2FChallenge.deserialize(self, serialized)

    def serialize(self):
        return json.dumps({
            'appId': self.app_id,
            'facets': self.facets,
            'response': self.response.serialize()
        })

    @classmethod
    def deserialize(cls, serialized):
        data = json.loads(serialized)
        return cls(data['appId'], data['facets'],
                   RawRegistrationResponse.deserialize(data['response']))


class U2FChallenge(object):

    """
    A U2F challenge object representing an assertion challenge for a registered
    U2F device.

    """

    TYPE_GET_ASSERTION = "navigator.id.getAssertion"

    def __init__(self, binding, challenge=None):
        self.binding = binding
        self.app_param = H(binding.app_id.encode('idna'))

        if challenge is None:
            self.challenge = os.urandom(32)
        else:
            self.challenge = challenge

    def _validate_client_data(self, client_data):
        """
        clientData = {
            "typ": TYPE_GET_ASSERTION,
            "challenge": string, //b64 encoded challenge.
            "origin": string, //Facet used
        }

        """

        if client_data.typ != self.TYPE_GET_ASSERTION:
            raise ValueError("Wrong type! Was: %s, expecting: %s" % (
                client_data.typ, self.TYPE_GET_ASSERTION))

        if self.challenge != client_data.challenge:
            raise ValueError("Wrong challenge! Was: %s, expecting: %s" % (
                client_data.challenge.encode('hex'),
                self.challenge.encode('hex')))

        if client_data.origin not in self.binding.facets:
            raise ValueError("Invalid facet! Was: %s, expecting one of: %r" % (
                client_data.origin, self.binding.facets))

    def validate(self, response):
        """
        signResponse = {
            "clientData": string, //b64 encoded JSON of ClientData
            "signatureData": string, //b64 encoded raw sign response
            "challenge": string, //b64 encoded challenge, also in clientData, why is this here?
        }
        """
        if not isinstance(response, SignResponse):
            response = SignResponse(response)

        self._validate_client_data(response.clientData)

        raw_response = RawAuthenticationResponse(
            self.app_param,
            response.clientParam,
            websafe_decode(
                response['signatureData']))
        raw_response.verify_signature(self.binding.pub_key)

        return raw_response.counter_int, raw_response.user_presence

    @property
    def data(self):
        """Return a SignRequest."""
        return SignRequest({
            'version': VERSION,
            'challenge': websafe_encode(self.challenge),
            'appId': self.binding.app_id,
            'keyHandle': websafe_encode(self.binding.key_handle)
        })

    @property
    def json(self):
        """Return a JSON SignRequest object to be sent to the client."""
        return self.data.json

    def serialize(self):
        return json.dumps({
            'challenge': websafe_encode(self.challenge)
        })

    @classmethod
    def deserialize(cls, binding, serialized):
        data = json.loads(serialized)
        return cls(binding, websafe_decode(data['challenge']))


enrollment = U2FEnrollment.__call__
deserialize_enrollment = U2FEnrollment.deserialize
deserialize_binding = U2FBinding.deserialize
