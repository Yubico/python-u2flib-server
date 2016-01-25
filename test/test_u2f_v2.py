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

from u2flib_server import u2f_v2 as u2f
from .soft_u2f_v2 import SoftU2FDevice
import unittest

APP_ID = 'http://www.example.com/appid'
FACET = 'https://www.example.com'
FACETS = [FACET]


class U2fV2Test(unittest.TestCase):

    def test_register_soft_u2f(self):
        token = SoftU2FDevice()

        request = u2f.start_register(APP_ID)
        response = token.register(request.json, FACET)

        device, cert = u2f.complete_register(request, response)
        assert device

    def test_authenticate_soft_u2f(self):
        token = SoftU2FDevice()
        request = u2f.start_register(APP_ID)
        response = token.register(request.json, FACET)
        device, cert = u2f.complete_register(request, response)

        challenge1 = u2f.start_authenticate(device)
        challenge2 = u2f.start_authenticate(device)

        response2 = token.getAssertion(challenge2.json, FACET)
        response1 = token.getAssertion(challenge1.json, FACET)

        assert u2f.verify_authenticate(device, challenge1, response1)
        assert u2f.verify_authenticate(device, challenge2, response2)

        try:
            u2f.verify_authenticate(device, challenge1, response2)
        except:
            pass
        else:
            assert False, "Incorrect validation should fail!"

        try:
            u2f.verify_authenticate(device, challenge2, response1)
        except:
            pass
        else:
            assert False, "Incorrect validation should fail!"

    def test_wrong_facet(self):
        token = SoftU2FDevice()
        request = u2f.start_register(APP_ID)
        response = token.register(request.json, "http://wrongfacet.com")

        try:
            u2f.complete_register(request, response, FACETS)
        except:
            pass
        else:
            assert False, "Incorrect facet should fail!"

        response2 = token.register(request.json, FACET)
        device, cert = u2f.complete_register(request, response2)

        challenge = u2f.start_authenticate(device)
        response = token.getAssertion(challenge.json, "http://notright.com")

        try:
            u2f.verify_authenticate(device, challenge, response, FACETS)
        except:
            pass
        else:
            assert False, "Incorrect facet should fail!"
