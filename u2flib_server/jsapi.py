from u2flib_server.utils import websafe_decode, sha_256
import json

__all__ = [
    'ClientData',
    'RegisterRequest',
    'RegisterResponse',
    'SignRequest',
    'SignResponse'
]


class JSONDict(dict):
    __getattr__ = dict.__getitem__

    def __init__(self, data=None):
        if isinstance(data, basestring):
            self.update(json.loads(data))
        elif isinstance(data, dict):
            self.update(data)
        else:
            raise TypeError("Unexpected type! Expected one of dict or string")

    @property
    def json(self):
        return json.dumps(self)


class ClientData(JSONDict):

    @property
    def challenge(self):
        return websafe_decode(self['challenge'])


class WithClientData(object):

    @property
    def clientData(self):
        return ClientData(websafe_decode(self['clientData']))

    @property
    def clientParam(self):
        return sha_256(websafe_decode(self['clientData']))


class RegisterRequest(JSONDict):
    pass


class RegisterResponse(JSONDict, WithClientData):

    @property
    def registrationData(self):
        return websafe_decode(self['registrationData'])


class SignRequest(JSONDict):
    pass


class SignResponse(JSONDict, WithClientData):

    @property
    def signatureData(self):
        return websafe_decode(self['signatureData'])
