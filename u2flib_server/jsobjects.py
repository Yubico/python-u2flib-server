from jsapi import (JSONDict, RegisterRequest, SignRequest)

__all__ = [
    'RegisterRequestData',
    'AuthenticateRequestData'
]


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
