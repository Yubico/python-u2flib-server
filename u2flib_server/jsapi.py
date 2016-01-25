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
        return [SignRequest(req) for req in self['authenticateRequests']]

    @property
    def registerRequests(self):
        return [RegisterRequest(req) for req in self['registerRequests']]

    def getRegisterRequest(self, response):
        return self.registerRequests[0]


class AuthenticateRequestData(JSONDict):

    @property
    def authenticateRequests(self):
        return [SignRequest(req) for req in self['authenticateRequests']]

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
        return [Selector(selector) for selector in selectors]


class MetadataObject(JSONDict):

    @property
    def vendorInfo(self):
        return VendorInfo(self['vendorInfo'])

    @property
    def devices(self):
        return [DeviceInfo(dev) for dev in self['devices']]
