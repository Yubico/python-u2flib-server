from jsapi import (JSONDict, RegisterRequest, RegisterResponse,
                                 SignRequest, SignResponse)

__all__ = [
    'RegisterRequestData',
    'RegisterResponseData',
    'AuthenticateRequestData',
    'AuthenticateResponseData'
]


class WithProps(object):

    @property
    def properties(self):
        return self.get('properties', {})


class RegisterRequestData(JSONDict):

    @property
    def authenticateRequests(self):
        return map(SignRequest, self['authenticateRequests'])

    @property
    def registerRequests(self):
        return map(RegisterRequest, self['registerRequests'])


class AuthenticateRequestData(JSONDict):

    @property
    def authenticateRequests(self):
        return map(SignRequest, self['authenticateRequests'])

