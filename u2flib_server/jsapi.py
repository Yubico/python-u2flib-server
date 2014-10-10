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

    def __init__(self, *args, **kwargs):
        if len(args) == 1:
            data = args[0]
        elif len(args) == 0:
            data = kwargs
        else:
            raise TypeError("Wrong number of arguments given!")

        if isinstance(data, basestring):
            self.update(json.loads(data))
        elif isinstance(data, dict):
            self.update(data)
        else:
            raise TypeError("Unexpected type! Expected one of dict or string")

    def __getattr__(self, key):
        try:
            return self[key]
        except KeyError:
            raise AttributeError("'%s' object has no attribute '%s'" %
                                 (type(self).__name__, key))

    @property
    def json(self):
        return json.dumps(self)


class WithAppId(object):

    @property
    def appParam(self):
        return sha_256(self['appId'].encode('idna'))


class WithChallenge(object):

    @property
    def challenge(self):
        return websafe_decode(self['challenge'])


class ClientData(JSONDict, WithChallenge):
    pass


class WithClientData(object):

    @property
    def clientData(self):
        return ClientData(websafe_decode(self['clientData']))

    @property
    def clientParam(self):
        return sha_256(websafe_decode(self['clientData']))


class RegisterRequest(JSONDict, WithAppId, WithChallenge):
    pass


class RegisterResponse(JSONDict, WithClientData):

    @property
    def registrationData(self):
        return websafe_decode(self['registrationData'])


class SignRequest(JSONDict, WithAppId, WithChallenge):
    pass


class SignResponse(JSONDict, WithClientData):

    @property
    def signatureData(self):
        return websafe_decode(self['signatureData'])
