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
from u2flib_server.utils import (pub_key_from_der, sha_256, websafe_decode,
                                 websafe_encode)
import json
import os
import struct

__all__ = ['U2FEnrollment', 'U2FBinding', 'U2FChallenge']

H = sha_256

VERSION = 'U2F_V2'


class RegistrationResponse(object):

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

    @staticmethod
    def deserialize(serialized):
        data = websafe_decode(serialized)
        return RegistrationResponse(data[:32], data[32:64], data[64:])


class AuthenticationResponse(object):

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

    @staticmethod
    def deserialize(serialized):
        data = websafe_decode(serialized)
        return AuthenticationResponse(data[:32], data[32:64], data[64:])


class U2FEnrollment(object):

    """
    A U2F enrollment object representing an incompleted registration.

    registrationData = {
        "version": "v2",
        "challenge": string //b64 encoded challenge, 32 bytes?
        "app_id": string //A URL pointing to a list of approved facets.
        "sessionId" string //Optional server state, will be passed back
    }

    """

    TYPE_FINISH_ENROLLMENT = "navigator.id.finishEnrollment"

    def __init__(self, app_id, facets=None, challenge=None, session_id=None):
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

        if session_id is None:
            self.session_id = ""
        else:
            self.session_id = session_id

    def _validate_client_data(self, client_data):
        """
        Validate the client data.

        clientData = {
            "typ": TYPE_FINISH_ENROLLMENT,
            "challenge": string, //b64 encoded challenge.
            "origin": string, //Facet used
        }

        """
        if client_data['typ'] != self.TYPE_FINISH_ENROLLMENT:
            raise ValueError("Wrong type! Was: %s, expecting: %s" % (
                client_data['typ'], self.TYPE_FINISH_ENROLLMENT))

        challenge = websafe_decode(client_data['challenge'])
        if self.challenge != challenge:
            raise ValueError("Wrong challenge! Was: %s, expecting: %s" % (
                challenge.encode('hex'), self.challenge.encode('hex')))

        if client_data['origin'] not in self.facets:
            raise ValueError("Invalid facet! Was: %s, expecting one of: %r" % (
                client_data['origin'], self.facets))

    def bind(self, response):
        """
        Complete registration, returning a U2FBinding.

        registrationResponse = {
            "registrationData": string, //b64 encoded raw registration response
            "bd": string, //b64 encoded JSON of ClientData
            "sessionId": string //Same as in registationData
        }

        """
        if isinstance(response, basestring):
            response = json.loads(response)

        if self.session_id != websafe_decode(response['sessionId']):
            raise ValueError("Wrong sessionId! Was: %s, expecting: %s" % (
                websafe_decode(response['sessionId']), self.session_id))

        client_data = websafe_decode(response['bd'])
        client_param = H(client_data)

        self._validate_client_data(json.loads(client_data))

        response = RegistrationResponse(
            self.app_param,
            client_param,
            websafe_decode(response['registrationData'])
        )

        response.verify_csr_signature()
        # TODO: Validate the certificate as well

        return U2FBinding(self.app_id, self.facets, response)

    @property
    def json(self):
        """Return a JSON RegistrationData object to be sent to the client."""
        return json.dumps({
            'version': VERSION,
            'challenge': websafe_encode(self.challenge),
            'app_id': self.app_id,
            'sessionId': websafe_encode(self.session_id)
        })

    def serialize(self):
        return json.dumps({
            'app_id': self.app_id,
            'facets': self.facets,
            'challenge': websafe_encode(self.challenge),
            'sessionId': websafe_encode(self.session_id)
        })

    @staticmethod
    def deserialize(serialized):
        data = json.loads(serialized)
        return U2FEnrollment(data['app_id'], data['facets'],
                             websafe_decode(data['challenge']),
                             websafe_decode(data['sessionId']))


class U2FBinding(object):

    """A U2F binding object representing a completed registration."""

    def __init__(self, app_id, facets, response):
        self.app_id = app_id
        self.facets = facets
        self.pub_key = response.pub_key
        self.key_handle = response.key_handle
        self.certificate = response.certificate
        self.response = response

    def make_challenge(self):
        return U2FChallenge(self)

    def deserialize_challenge(self, serialized):
        return U2FChallenge.deserialize(self, serialized)

    def serialize(self):
        return json.dumps({
            'app_id': self.app_id,
            'facets': self.facets,
            'response': self.response.serialize()
        })

    @staticmethod
    def deserialize(serialized):
        data = json.loads(serialized)
        return U2FBinding(data['app_id'], data['facets'],
                          RegistrationResponse.deserialize(data['response']))


class U2FChallenge(object):

    """
    A U2F challenge object representing an assertion challenge for a registered
    U2F device.

    """

    TYPE_GET_ASSERTION = "navigator.id.getAssertion"

    def __init__(self, binding, challenge=None, session_id=None):
        self.binding = binding
        self.app_param = H(binding.app_id.encode('idna'))

        if challenge is None:
            self.challenge = os.urandom(32)
        else:
            self.challenge = challenge

        if session_id is None:
            self.session_id = ""
        else:
            self.session_id = session_id

    def _validate_client_data(self, client_data):
        """
        clientData = {
            "typ": TYPE_GET_ASSERTION,
            "challenge": string, //b64 encoded challenge.
            "origin": string, //Facet used
        }

        """

        if client_data['typ'] != self.TYPE_GET_ASSERTION:
            raise ValueError("Wrong type! Was: %s, expecting: %s" % (
                client_data['typ'], self.TYPE_GET_ASSERTION))

        challenge = websafe_decode(client_data['challenge'])
        if self.challenge != challenge:
            print "%r != %r" % (self.challenge, challenge)
            raise ValueError("Wrong challenge! Was: %s, expecting: %s" % (
                challenge.encode('hex'), self.challenge.encode('hex')))

        if client_data['origin'] not in self.binding.facets:
            raise ValueError("Invalid facet! Was: %s, expecting one of: %r" % (
                client_data['origin'], self.binding.facets))

    def validate(self, response):
        """
        signResponse = {
            "bd": string, //b64 encoded JSON of ClientData
            "sign": string, //b64 encoded raw sign response
            "challenge": string, //b64 encoded challenge, also in bd, why is this here?
            "sessionId": string, //Same as in signData
            "app_id": string //app_id
        }
        """
        if isinstance(response, basestring):
            response = json.loads(response)

        if response['app_id'] != self.binding.app_id:
            raise ValueError("Invalid app_id! Was: %s, expecting: %s" % (
                response['app_id'], self.app_id))

        if self.session_id != websafe_decode(response['sessionId']):
            raise ValueError("Wrong sessionId! Was: %s, expecting: %s" % (
                websafe_decode(response['sessionId']), self.session_id))

        client_data = websafe_decode(response['bd'])
        client_param = H(client_data)

        self._validate_client_data(json.loads(client_data))

        response = AuthenticationResponse(self.app_param, client_param,
                                          websafe_decode(response['sign']))
        response.verify_signature(self.binding.pub_key)

        return response.counter_int, response.user_presence

    @property
    def json(self):
        """Return a JSON SignData object to be sent to the client."""
        return json.dumps({
            'version': VERSION,
            'challenge': websafe_encode(self.challenge),
            'app_id': self.binding.app_id,
            'key_handle': websafe_encode(self.binding.key_handle),
            'sessionId': websafe_encode(self.session_id)
        })

    def serialize(self):
        return json.dumps({
            'challenge': websafe_encode(self.challenge),
            'sessionId': websafe_encode(self.session_id)
        })

    @staticmethod
    def deserialize(binding, serialized):
        data = json.loads(serialized)
        return U2FChallenge(binding, websafe_decode(data['challenge']),
                            websafe_decode(data['sessionId']))


enrollment = U2FEnrollment.__call__
deserialize_enrollment = U2FEnrollment.deserialize
deserialize_binding = U2FBinding.deserialize
