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
from soft_u2f_v2 import SoftU2FDevice
import unittest

APP_ID = 'http://www.example.com/appid'
FACET = 'https://www.example.com'
FACETS = [FACET]


class U2fV2Test(unittest.TestCase):

    def test_register_fixed_values(self):
        token = SoftU2FDevice()
        request = {"challenge": "KEzvDDdHwnXtPHIMb0Uh43hgOJ-wQTsdLujGkeg6JxM", "version": "U2F_V2", "appId": "http://localhost:8081"}
        response = {"registrationData": "BQS94xQL46G4vheJPkYSuEteM6Km4-MwgBAu1zZ6MAbjDDgqhYbpHuIhhGOKjedeDd58qqktqOJsby9wMdHGnUtVQD8ISPywVi3J6SaKebCVQdHPu3_zQigRS8LhoDwKT5Ed3tg8AWuNw9XBZEh4doEDxKGuInFazirUw8acOu2qDcEwggIjMIIBDaADAgECAgRyuHt0MAsGCSqGSIb3DQEBCzAPMQ0wCwYDVQQDEwR0ZXN0MB4XDTE1MDkwNDA3MTAyNloXDTE2MDkwMzA3MTAyNlowKjEoMCYGA1UEAxMfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTkyNDY5Mjg1MjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABC37i_h-xmEtGfWnuvj_BmuhtU18MKShNP_vZ7C2WJwj8OHaSLnzAfha14CMUPaKPtRFfP6w9CFGhvEizH33XZKjOzA5MCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS4yMBMGCysGAQQBguUcAgEBBAQDAgQwMAsGCSqGSIb3DQEBCwOCAQEAab7fWlJ-lOR1sqIxawPU5DWZ1b9nQ0QmNNoetPHJ_fJC95r0esRq5axfmGufbNktNWanHww7i9n5WWxSaMTWuJSF0eAXUajo8odYA8nB4_0I6z615MWa9hTU64Pl9HlqkR5ez5jndmJNuAfhaIF4h062Jw051kMo_aENxuLixnybTfJG7Q5KRE00o2MFs5b9L9fzhDtBzv5Z-vGOefuiohowpwnxIA9l0tGqrum9plUdx06K9TqKMRDQ8naosy01rbouA6i5xVjl-tHT3z-r__FYcSZ_dQ5-SCPOh4F0w6T0UwzymQmeqYN3pP-UUgnJ-ihD-uhEWklKNYRy0K0G0jBGAiEA7rbbx2jwC1YGICkZMR07ggKWaHCwFBxNDW3OwhLNNzUCIQCSq0sjGSUnWMQgPEImrmd3tMKcbrjI995rti6UYozqsg", "clientData": "eyJvcmlnaW4iOiAiaHR0cDovL2xvY2FsaG9zdDo4MDgxIiwgImNoYWxsZW5nZSI6ICJLRXp2RERkSHduWHRQSElNYjBVaDQzaGdPSi13UVRzZEx1akdrZWc2SnhNIiwgInR5cCI6ICJuYXZpZ2F0b3IuaWQuZmluaXNoRW5yb2xsbWVudCJ9"}
        u2f.complete_register(request, response)

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
