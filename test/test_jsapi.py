# Copyright (c) 2015 Yubico AB
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

import unittest

from u2flib_server.jsapi import (
    JSONDict,
    DeviceRegistration, ClientData,
    RegisterRequest, RegisterResponse,
    SignRequest, SignResponse,
    RegisterRequestData, AuthenticateRequestData,
    VendorInfo, Selector,
    DeviceInfo, MetadataObject,
)


class JSONDictTest(unittest.TestCase):
    def test_create(self):
        self.assertEqual({}, JSONDict())

    def test_create_from_bytes(self):
        self.assertEqual({'a': 1, 'b': 2}, JSONDict(b'{"a":1,"b":2}'))

    def test_create_from_unicode(self):
        self.assertEqual({'a': 1, 'b': 2}, JSONDict(u'{"a":1,"b":2}'))

    def test_create_from_dict(self):
        self.assertEqual({'a': 1, 'b': 2}, JSONDict({'a': 1, 'b': 2}))

    def test_create_from_kwargs(self):
        self.assertEqual({'a': 1, 'b': 2}, JSONDict(a=1, b=2))

    def test_create_wrong_type(self):
        # NB: This is differs from dict behaviour
        self.assertRaises(TypeError, JSONDict, [])
        self.assertRaises(TypeError, JSONDict, [('a', 1), ('b', 2)])

    def test_create_wrong_nargs(self):
        self.assertRaises(TypeError, JSONDict, {}, {})
        self.assertRaises(TypeError, JSONDict, {'a': 1}, {'b': 2})

    def test_json(self):
        self.assertEqual('{}', JSONDict().json)
        self.assertEqual('{"a": 1}', JSONDict(a=1).json)

    def test_wrap(self):
        self.assertTrue(isinstance(JSONDict.wrap({}), JSONDict))

    def test_getattr_unknown(self):
        self.assertRaises(AttributeError, lambda: JSONDict().foo)

    def test_getattr(self):
        self.assertEqual(1, JSONDict(a=1).a)


class DeviceRegistrationTest(unittest.TestCase):
    def test_appParam(self):
        obj = DeviceRegistration(appId='https://example.com')
        self.assertEqual('\x10\x06\x80\xadTl\xe6\xa5w\xf4/R\xdf3\xb4\xcf'
                         '\xdc\xa7V\x85\x9efK\x8d}\xe3)\xb1P\xd0\x9c\xe9',
                         obj.appParam)


class ClientDataTest(unittest.TestCase):
    def test_challenge(self):
        obj = ClientData(challenge='Zm9vYmFy')
        self.assertEqual('foobar', obj.challenge)


class RegisterRequestTest(unittest.TestCase):
    def test_appParam(self):
        req = RegisterRequest(appId='https://example.com')
        self.assertEqual('\x10\x06\x80\xadTl\xe6\xa5w\xf4/R\xdf3\xb4\xcf'
                         '\xdc\xa7V\x85\x9efK\x8d}\xe3)\xb1P\xd0\x9c\xe9',
                         req.appParam)

    def test_challenge(self):
        req = RegisterRequest(challenge='Zm9vYmFy')
        self.assertEqual('foobar', req.challenge)

class RegisterResponseTest(unittest.TestCase):
    def test_clientData(self):
        obj = RegisterResponse(clientData='eyJhIjoxfQ')
        self.assertEqual({'a': 1}, obj.clientData)
        self.assertTrue(isinstance(obj.clientData, ClientData))

    def test_clientParam(self):
        obj = RegisterResponse(clientData='eyJhIjoxfQ')
        self.assertEqual("\x01Z\xbd\x7f\\\xc5z-\xd9Ku\x90\xf0J\xd8\x08"
                         "Bs\x90^\xe3>\xc5\xce\xbe\xaeb'j\x97\xf8b",
                         obj.clientParam)

    def test_registrationData(self):
        pass


class SignRequestTest(unittest.TestCase):
    def test_appParam(self):
        req = SignRequest(appId='https://example.com')
        self.assertEqual('\x10\x06\x80\xadTl\xe6\xa5w\xf4/R\xdf3\xb4\xcf'
                         '\xdc\xa7V\x85\x9efK\x8d}\xe3)\xb1P\xd0\x9c\xe9',
                         req.appParam)

    def test_challenge(self):
        req = SignRequest(challenge='Zm9vYmFy')
        self.assertEqual('foobar', req.challenge)


class SignResponseTest(unittest.TestCase):
    def test_clientData(self):
        obj = SignResponse(clientData='eyJhIjoxfQ')
        self.assertEqual({'a': 1}, obj.clientData)
        self.assertTrue(isinstance(obj.clientData, ClientData))

    def test_clientParam(self):
        obj = SignResponse(clientData='eyJhIjoxfQ')
        self.assertEqual("\x01Z\xbd\x7f\\\xc5z-\xd9Ku\x90\xf0J\xd8\x08"
                         "Bs\x90^\xe3>\xc5\xce\xbe\xaeb'j\x97\xf8b",
                         obj.clientParam)

    def test_signatureData(self):
        response = SignResponse(signatureData='eyJhIjoxfQ')
        self.assertEqual('{"a":1}', response.signatureData)


class RegisterRequestDataTest(unittest.TestCase):
    def test_authenticateRequests(self):
        reqdata = RegisterRequestData(authenticateRequests=[{}, {'a': 1}, {'a': 1, 'b': 2}])
        self.assertEqual([{}, {'a': 1}, {'a': 1, 'b': 2}], reqdata.authenticateRequests)
        self.assertTrue(isinstance(reqdata.authenticateRequests[0], SignRequest))

    def test_registerRequests(self):
        reqdata = RegisterRequestData(registerRequests=[{}, {'a': 1}, {'a': 1, 'b': 2}])
        self.assertEqual([{}, {'a': 1}, {'a': 1, 'b': 2}], reqdata.registerRequests)
        self.assertTrue(isinstance(reqdata.registerRequests[0], RegisterRequest))

    def test_getRegisterRequest(self):
        reqdata = RegisterRequestData(registerRequests=[{}, {'a': 1}, {'a': 1, 'b': 2}])
        response = None
        self.assertEqual({}, reqdata.getRegisterRequest(response))
        self.assertTrue(isinstance(reqdata.getRegisterRequest(response), RegisterRequest))


class AuthenticateRequestDataTest(unittest.TestCase):
    def test_authenticateRequests(self):
        reqdata = AuthenticateRequestData(authenticateRequests=[{}, {'a': 1}, {'a': 1, 'b': 2}])
        self.assertEqual([{}, {'a': 1}, {'a': 1, 'b': 2}], reqdata.authenticateRequests)
        self.assertTrue(isinstance(reqdata.authenticateRequests[0], SignRequest))

    def test_getAuthenticateRequest(self):
        reqdata = AuthenticateRequestData(authenticateRequests=[{'keyHandle': 'a'},
                                                                {'keyHandle': 'b'}])
        response = SignResponse(keyHandle='b')
        self.assertEqual({'keyHandle': 'b'}, reqdata.getAuthenticateRequest(response))
        self.assertTrue(isinstance(reqdata.getAuthenticateRequest(response), SignRequest))


class DeviceInfoTest(unittest.TestCase):
    def test_selectors_empty(self):
        self.assertTrue(DeviceInfo().selectors is None)

    def test_selectors(self):
        devinfo = DeviceInfo(selectors=[{}, {'a': 1}, {'a': 1, 'b': 2}])
        self.assertEqual([{}, {'a': 1}, {'a': 1, 'b': 2}], devinfo.selectors)
        self.assertTrue(isinstance(devinfo.selectors[0], Selector))
        self.assertTrue(isinstance(devinfo.selectors[1], Selector))
        self.assertTrue(isinstance(devinfo.selectors[2], Selector))


class MetadataObjectTest(unittest.TestCase):
    def test_vendorinfo(self):
        metadata = MetadataObject(vendorInfo={})
        self.assertEqual({}, metadata.vendorInfo)
        self.assertTrue(isinstance(metadata.vendorInfo, VendorInfo))

    def test_devices(self):
        metadata = MetadataObject(devices=[{}, {'a': 1}, {'a': 1, 'b': 2}])
        self.assertEqual([{}, {'a': 1}, {'a': 1, 'b': 2}], metadata.devices)
        self.assertTrue(isinstance(metadata.devices[0], DeviceInfo))
        self.assertTrue(isinstance(metadata.devices[1], DeviceInfo))
        self.assertTrue(isinstance(metadata.devices[2], DeviceInfo))
