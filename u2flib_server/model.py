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


from u2flib_server.utils import websafe_encode, websafe_decode, sha_256
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_der_public_key
from binascii import a2b_hex
from enum import Enum
import struct
import json
import six
import os


__all__ = [
    'Transport',
    'Type',
    'RegistrationData',
    'SignatureData',
    'RegisteredKey',
    'DeviceRegistration',
    'ClientData',
    'RegisterRequest',
    'RegisterResponse',
    'SignResponse',
    'U2fRegisterRequest',
    'U2fSignRequest'
]


U2F_V2 = 'U2F_V2'

TRANSPORTS_EXT_OID = x509.ObjectIdentifier('1.3.6.1.4.1.45724.2.1.1')
PUB_KEY_DER_PREFIX = a2b_hex(
    '3059301306072a8648ce3d020106082a8648ce3d030107034200')

CERTS_TO_FIX = [
    a2b_hex('349bca1031f8c82c4ceca38b9cebf1a69df9fb3b94eed99eb3fb9aa3822d26e8'),
    a2b_hex('dd574527df608e47ae45fbba75a2afdd5c20fd94a02419381813cd55a2a3398f'),
    a2b_hex('1d8764f0f7cd1352df6150045c8f638e517270e8b5dda1c63ade9c2280240cae'),
    a2b_hex('d0edc9a91a1677435a953390865d208c55b3183c6759c9b5a7ff494c322558eb'),
    a2b_hex('6073c436dcd064a48127ddbf6032ac1a66fd59a0c24434f070d4e564c124c897'),
    a2b_hex('ca993121846c464d666096d35f13bf44c1b05af205f9b4a1e00cf6cc10c5e511')
]


def _parse_tlv_size(tlv):
    l = six.indexbytes(tlv, 1)
    n_bytes = 1
    if l > 0x80:
        n_bytes = l - 0x80
        l = 0
        for i in range(2, 2 + n_bytes):
            l = l * 256 + six.indexbytes(tlv, i)
    return 2 + n_bytes + l


def _pop_bytes(data, l):
    x = bytes(data[:l])
    del data[:l]
    return x


def _fix_cert(der):  # Some early certs have UNUSED BITS incorrectly set.
    if sha_256(der) in CERTS_TO_FIX:
        der = der[:-257] + b'\0' + der[-256:]
    return der


def _validate_client_data(client_data, challenge, typ, valid_facets):
    if client_data.typ != typ:
        raise ValueError("Wrong type! Was: %r, expecting: %r" % (
            client_data.typ, typ))

    if challenge != client_data.challenge:
        raise ValueError("Wrong challenge! Was: %r, expecting: %r" % (
            client_data.challenge, challenge))

    if valid_facets is not None and client_data.origin not in valid_facets:
        raise ValueError("Invalid facet! Was: %r, expecting one of: %r" % (
            client_data.origin, valid_facets))


class Transport(Enum):
    BT = 0x01  # Bluetooth Classic
    BLE = 0x02  # Bluetooth Low Energy
    USB = 0x04
    NFC = 0x08

    @property
    def key(self):
        return self.name.lower()

    @staticmethod
    def transports_from_cert(cert):
        if isinstance(cert, bytes):
            cert = x509.load_der_x509_certificate(cert, default_backend())
        try:
            ext = cert.extensions.get_extension_for_oid(TRANSPORTS_EXT_OID)
            der_bitstring = ext.value.value
            int_bytes = bytearray(der_bitstring[3:])

            # Mask away unused bits (should already be 0, but make sure)
            unused_bits = six.indexbytes(der_bitstring, 2)
            int_bytes[-1] &= (0xff << unused_bits)

            # Reverse the bitstring and convert to integer
            transports = 0
            for byte in int_bytes:
                for _ in range(8):
                    transports = (transports << 1) | (byte & 1)
                    byte >>= 1
            return [t for t in Transport if t.value & transports]
        except x509.ExtensionNotFound:
            return None


class Type(Enum):
    REGISTER = 'navigator.id.finishEnrollment'
    SIGN = 'navigator.id.getAssertion'


class RegistrationData(object):

    def __init__(self, data):
        if isinstance(data, six.text_type):
            data = websafe_decode(data)

        buf = bytearray(data)
        if buf.pop(0) != 0x05:
            raise ValueError('Reserved byte value must be 0x05')
        self.pub_key = _pop_bytes(buf, 65)
        self.key_handle = _pop_bytes(buf, buf.pop(0))
        cert_len = _parse_tlv_size(buf)
        self.certificate = _fix_cert(_pop_bytes(buf, cert_len))
        self.signature = bytes(buf)

    @property
    def keyHandle(self):
        return websafe_encode(self.key_handle)

    @property
    def publicKey(self):
        return websafe_encode(self.pub_key)

    def verify(self, app_param, chal_param):
        cert = x509.load_der_x509_certificate(self.certificate,
                                              default_backend())
        pubkey = cert.public_key()
        verifier = pubkey.verifier(self.signature, ec.ECDSA(hashes.SHA256()))

        verifier.update(b'\0' + app_param + chal_param + self.key_handle +
                        self.pub_key)
        verifier.verify()

    @property
    def bytes(self):
        return (
            six.int2byte(0x05) +
            self.pub_key +
            six.int2byte(len(self.key_handle)) +
            self.key_handle +
            self.certificate +
            self.signature
        )


class SignatureData(object):

    def __init__(self, data):
        if isinstance(data, six.text_type):
            data = websafe_decode(data)

        buf = bytearray(data)
        self.user_presence = buf.pop(0)
        self.counter = struct.unpack('>I', _pop_bytes(buf, 4))[0]
        self.signature = bytes(buf)

    def verify(self, app_param, chal_param, der_pubkey):
        pubkey = load_der_public_key(PUB_KEY_DER_PREFIX + der_pubkey,
                                     default_backend())
        verifier = pubkey.verifier(self.signature, ec.ECDSA(hashes.SHA256()))
        verifier.update(app_param +
                        six.int2byte(self.user_presence) +
                        struct.pack('>I', self.counter) +
                        chal_param)
        verifier.verify()

    @property
    def bytes(self):
        return (
            six.int2byte(self.user_presence) +
            struct.pack('>I', self.counter) +
            self.signature
        )


class JSONDict(dict):
    _required_fields = []

    def __init__(self, *args, **kwargs):
        if len(args) == 1 and not kwargs:
            arg = args[0]
            args = tuple()
            if isinstance(arg, six.text_type):
                kwargs = json.loads(arg)
            elif isinstance(arg, six.binary_type):
                kwargs = json.loads(arg.decode('utf-8'))
            else:
                kwargs = dict(arg)
        super(JSONDict, self).__init__(*args, **kwargs)

        missing = set(self._required_fields).difference(self.keys())
        if missing:
            raise ValueError('Missing required fields: %s' % ', '.join(missing))

    def __getattr__(self, key):
        try:
            return self[key]
        except KeyError:
            raise AttributeError("'%s' object has no attribute '%s'" %
                                 (type(self).__name__, key))

    @property
    def json(self):
        return json.dumps(self)

    @classmethod
    def wrap(cls, data):
        return data if isinstance(data, cls) else cls(data)


class WithAppId(object):

    @property
    def applicationParameter(self):
        return sha_256(self['appId'].encode('idna'))


class WithChallenge(object):

    @property
    def challenge(self):
        return websafe_decode(self['challenge'])


class WithKeyHandle(object):

    @property
    def keyHandle(self):
        return websafe_decode(self['keyHandle'])


class RegisteredKey(JSONDict, WithAppId, WithKeyHandle):
    _required_fields = ['version', 'keyHandle']

    @property
    def key_data(self):
        data = {
            'version': self['version'],
            'keyHandle': self['keyHandle']
        }
        if 'appId' in self:
            data['appId'] = self['appId']
        if self.get('transports') is not None:
            data['transports'] = self['transports']
        return data

    @property
    def transports(self):
        if 'transports' in self:
            return [getattr(Transport, x.upper()) for x in self['transports']]
        return None


class DeviceRegistration(RegisteredKey):
    _required_fields = ['version', 'keyHandle', 'publicKey']

    @property
    def publicKey(self):
        return websafe_decode(self['publicKey'])


class ClientData(JSONDict, WithChallenge):
    _required_fields = ['typ', 'challenge', 'origin']

    def __init__(self, *args, **kwargs):
        if len(args) == 1:
            data = args[0]
            if isinstance(data, six.binary_type):
                data = data.decode('utf-8')
            try:
                args = [websafe_decode(data)]
            except ValueError:
                pass  # Not encoded, leave as is

        super(ClientData, self).__init__(*args, **kwargs)

    @property
    def typ(self):
        return Type(self['typ'])


class WithClientData(object):

    @property
    def clientData(self):
        return ClientData.wrap(self['clientData'])

    @property
    def challengeParameter(self):
        return sha_256(websafe_decode(self['clientData']))


class RegisterRequest(JSONDict, WithAppId, WithChallenge):
    _required_fields = ['version', 'challenge']


class RegisterResponse(JSONDict, WithClientData):
    _required_fields = ['version', 'registrationData', 'clientData']

    @property
    def registrationData(self):
        return RegistrationData(self['registrationData'])

    def verify(self, app_param):
        self.registrationData.verify(app_param, self.challengeParameter)


class SignResponse(JSONDict, WithClientData, WithKeyHandle):
    _required_fields = ['keyHandle', 'signatureData', 'clientData']

    @property
    def signatureData(self):
        return SignatureData(self['signatureData'])

    def verify(self, app_param, der_pubkey):
        self.signatureData.verify(app_param, self.challengeParameter,
                                  der_pubkey)


class WithRegisteredKeys(object):

    @property
    def registeredKeys(self):
        return [RegisteredKey.wrap(x) for x in self['registeredKeys']]


class U2fRegisterRequest(JSONDict, WithAppId, WithRegisteredKeys):
    _required_fields = ['appId', 'registerRequests', 'registeredKeys']

    @property
    def registerRequests(self):
        return [RegisterRequest.wrap(x) for x in self['registerRequests']]

    def get_request(self, version):
        for req in self.registerRequests:
            if req.version == version:
                return req
        raise ValueError('No RegisterRequest found for version: %s' % version)

    @property
    def data_for_client(self):
        return {
            'appId': self['appId'],
            'registerRequests': self['registerRequests'],
            'registeredKeys': [r.key_data for r in self.registeredKeys]
        }

    @classmethod
    def create(cls, app_id, registered_keys, challenge=None):
        if challenge is None:
            challenge = os.urandom(32)

        return cls(
            appId=app_id,
            registerRequests=[RegisterRequest(
                version=U2F_V2,
                challenge=websafe_encode(challenge)
            )],
            registeredKeys=registered_keys
        )

    def complete(self, response, valid_facets=None):
        resp = RegisterResponse.wrap(response)
        req = self.get_request(U2F_V2)

        _validate_client_data(resp.clientData, req.challenge, Type.REGISTER,
                              valid_facets)

        resp.verify(self.applicationParameter)
        registration_data = resp.registrationData
        transports = Transport.transports_from_cert(
            registration_data.certificate)
        transports = [t.key for t in transports] if transports else transports

        return DeviceRegistration(
            version=req.version,
            keyHandle=registration_data.keyHandle,
            appId=self.appId,
            publicKey=registration_data.publicKey,
            transports=transports,
        ), registration_data.certificate


class U2fSignRequest(JSONDict, WithAppId, WithChallenge, WithRegisteredKeys):
    _required_fields = ['appId', 'challenge', 'registeredKeys']

    @property
    def data_for_client(self):
        return {
            'appId': self['appId'],
            'challenge': self['challenge'],
            'registeredKeys': [r.key_data for r in self.registeredKeys]
        }

    @property
    def devices(self):
        return [DeviceRegistration.wrap(x) for x in self['registeredKeys']]

    @classmethod
    def create(cls, app_id, devices, challenge=None):
        if challenge is None:
            challenge = os.urandom(32)

        return cls(
            appId=app_id,
            registeredKeys=devices,
            challenge=websafe_encode(challenge)
        )

    def complete(self, response, valid_facets=None):
        resp = SignResponse.wrap(response)

        _validate_client_data(resp.clientData, self.challenge, Type.SIGN,
                              valid_facets)
        device = next(d for d in self.devices if d.keyHandle == resp.keyHandle)

        app_param = device.applicationParameter \
            if 'appId' in device else self.applicationParameter
        resp.verify(app_param, device.publicKey)

        sign_data = resp.signatureData

        return sign_data.counter, sign_data.user_presence
