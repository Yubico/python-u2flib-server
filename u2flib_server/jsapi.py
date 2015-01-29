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

from u2flib_server.utils import websafe_decode, sha_256
import json

__all__ = [
    'ClientData',
    'DeviceRegistration',
    'RegisterRequest',
    'RegisterResponse',
    'SignRequest',
    'SignResponse',
    'RegisterRequestData',
    'AuthenticateRequestData'
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

    @classmethod
    def wrap(cls, data):
        return data if isinstance(data, cls) else cls(data)


class WithAppId(object):

    @property
    def appParam(self):
        return sha_256(self['appId'].encode('idna'))


class WithChallenge(object):

    @property
    def challenge(self):
        return websafe_decode(self['challenge'])


class DeviceRegistration(JSONDict, WithAppId):
    pass


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


class RegisterRequestData(JSONDict):

    @property
    def authenticateRequests(self):
        return map(SignRequest, self['authenticateRequests'])

    @property
    def registerRequests(self):
        return map(RegisterRequest, self['registerRequests'])

    def getRegisterRequest(self, response):
        return self.registerRequests[0]


class AuthenticateRequestData(JSONDict):

    @property
    def authenticateRequests(self):
        return map(SignRequest, self['authenticateRequests'])

    def getAuthenticateRequest(self, response):
        return next(req for req in self.authenticateRequests
                    if req.keyHandle == response.keyHandle)


#
# Metadata
#


class VendorInfo(JSONDict):
    pass


class Selector(JSONDict):
    pass


class DeviceInfo(JSONDict):

    @property
    def selectors(self):
        selectors = self.get('selectors')
        if selectors is None:
            return None
        return map(Selector, selectors)


class MetadataObject(JSONDict):

    @property
    def vendorInfo(self):
        return VendorInfo(self['vendorInfo'])

    @property
    def devices(self):
        return map(DeviceInfo, self['devices'])
