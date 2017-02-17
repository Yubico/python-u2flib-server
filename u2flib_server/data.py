from u2flib_server.utils import websafe_encode, websafe_decode, sha_256
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_der_public_key
from enum import Enum
import struct
import json
import six
import os


U2F_V2 = 'U2F_V2'

PUB_KEY_DER_PREFIX = b'\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01' \
    b'\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00'


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


class RegistrationData(object):

    def __init__(self, data):
        if isinstance(data, six.text_type):
            data = websafe_decode(data)

        buf = bytearray(data)
        if buf.pop(0) != 0x05:
            raise ValueError('Reserved byte value must be 0x05')
        self.pubkey = _pop_bytes(buf, 65)
        self.key_handle = _pop_bytes(buf, buf.pop(0))
        cert_len = _parse_tlv_size(buf)
        self.certificate = _pop_bytes(buf, cert_len)
        self.signature = bytes(buf)

    @property
    def keyHandle(self):
        return websafe_encode(self.key_handle)

    def verify(self, app_param, chal_param):
        # TODO: Fix signature of certificate
        cert = x509.load_der_x509_certificate(self.certificate,
                                              default_backend())
        pubkey = cert.public_key()
        verifier = pubkey.verifier(self.signature, ec.ECDSA(hashes.SHA256()))

        verifier.update(b'\0' + app_param + chal_param + self.key_handle +
                        self.pubkey)
        verifier.verify()

    @property
    def bytes(self):
        return (
            six.int2byte(0x05) +
            self.pubkey +
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
            self.user_presence +
            struct.pack('>I', self.counter) +
            self.signature
        )


class Transport(Enum):
    BT = 0x01  # Bluetooth Classic
    BLE = 0x02  # Bluetooth Low Energy
    USB = 0x04
    NFC = 0x08


class Type(Enum):
    REGISTER = 'navigator.id.finishEnrollment'
    SIGN = 'navigator.id.getAssertion'


class JSONDict(dict):
    _required_fields = []

    def __init__(self, *args, **kwargs):
        if len(args) == 1:
            data = args[0]
        elif len(args) == 0:
            data = kwargs
        else:
            raise TypeError("Wrong number of arguments given!")

        if isinstance(data, six.text_type):
            self.update(json.loads(data))
        elif isinstance(data, six.binary_type):
            self.update(json.loads(data.decode('utf-8')))
        elif isinstance(data, dict):
            self.update(data)
        else:
            raise TypeError("Unexpected type! Expected a JSON string, or dict")

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
        if 'transports' in self:
            data['transports'] = self['transports']
        return data

    @property
    def transports(self):
        if 'transports' in self:
            return [getattr(Transport, x.upper()) for x in self['transports']]
        return None


class DeviceRegistration(RegisteredKey):
    _required_fields = ['version', 'keyHandle', 'publicKey']


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

    @property
    def transports(self):
        return None  # TODO

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

        return DeviceRegistration(
            version=req.version,
            keyHandle=registration_data.keyHandle,
            appId=self.appId,
            publicKey=registration_data.pubkey,
            transports=resp.transports,
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
