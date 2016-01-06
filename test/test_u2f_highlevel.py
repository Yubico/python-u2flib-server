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

from u2flib_server import u2f
from soft_u2f_v2 import SoftU2FDevice
import unittest

APP_ID = 'https://www.example.com'
FACET = APP_ID


def register_token(devices=[]):
    token = SoftU2FDevice()
    request_data = u2f.start_register(APP_ID, devices)
    response = token.register(request_data.registerRequests[0].json, FACET)
    device, cert = u2f.complete_register(request_data, response)
    return device, token


class AttestationTest(unittest.TestCase):

    def test_register_soft_u2f(self):
        device, token = register_token()
        assert device

    def test_authenticate_single_soft_u2f(self):
        # Register
        device, token = register_token()

        # Authenticate
        sign_request = u2f.start_authenticate([device])

        response1 = token.getAssertion(
            sign_request.authenticateRequests[0].json,
            FACET
        )

        assert u2f.verify_authenticate([device], sign_request, response1)

    def test_authenticate_multiple_soft_u2f(self):
        # Register
        device1, token1 = register_token()
        device2, token2 = register_token([device1])

        # Authenticate
        auth_request_data = u2f.start_authenticate([device1, device2])

        response = token1.getAssertion(
            auth_request_data.authenticateRequests[0].json,
            FACET
        )

        assert u2f.verify_authenticate([device1, device2],
                                       auth_request_data,
                                       response)
