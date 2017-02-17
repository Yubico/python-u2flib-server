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

from u2flib_server import data
from .soft_u2f_v2 import SoftU2FDevice
import unittest

APP_ID = 'https://www.example.com'
FACET = APP_ID


def register_token(devices=[]):
    token = SoftU2FDevice()
    request = data.U2fRegisterRequest.create(APP_ID, devices)
    response = token.register(FACET, request.appId,
                              request.registerRequests[0].json)
    device, cert = request.complete(response)
    return device, token


class AttestationTest(unittest.TestCase):

    def test_register_soft_u2f(self):
        device, token = register_token()
        assert device

    def test_authenticate_single_soft_u2f(self):
        # Register
        device, token = register_token()

        # Authenticate
        request = data.U2fSignRequest.create(APP_ID, [device])

        response = token.getAssertion(
            FACET,
            request.appId,
            request['challenge'],
            request.registeredKeys[0].key_data,
        )

        request.complete(response)

    def test_authenticate_multiple_soft_u2f(self):
        # Register
        device1, token1 = register_token()
        device2, token2 = register_token([device1])

        # Authenticate
        request = data.U2fSignRequest.create(APP_ID, [device1, device2])
        response = token1.getAssertion(
            FACET,
            request.appId,
            request['challenge'],
            request.registeredKeys[0].key_data,
        )

        request.complete(response)
