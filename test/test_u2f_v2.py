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

SAMPLE_REG_DATA = b'''\x05\x04E\'\x9c@\xa5n\xae\x06\xcb\x92\'\xf1`Q\xc2\xfe\xb1\xe2\x9er\x16\xbb\xd6\xaf\x1e\xbe\n\x9fC\x079B\xea\x90\x86\xfe*&\x82\xf7*\x94\x94)}S\xe9uI\x12\xac\x8e\x92s\xa4\xdf\xde\xf2\xd9\x18y\x9b\xfc\xe4@?p\xaeX\x0c[\xd1\x068i\x81CIJ!\xae\xfd\xbd\xc4%\xda\xd3\x05\xee\x19a62\x06\xac\x91\xf0\xed\x1a\xa0\xf3\x06\xe7)d\xafB;9\xca\xd2\xb7\xb3u\xfda\x1b\x8dq\x8d\xe1\xb7\x9aIa\x96\xc6k\xee0\x82\x01\x870\x82\x01.\xa0\x03\x02\x01\x02\x02\t\x00\x99\xbe\xe8\xb1\x0c\xa2\xec\x1c0\t\x06\x07*\x86H\xce=\x04\x010!1\x1f0\x1d\x06\x03U\x04\x03\x0c\x16Yubico U2F Soft Device0\x1e\x17\r130717142103Z\x17\r160716142103Z0!1\x1f0\x1d\x06\x03U\x04\x03\x0c\x16Yubico U2F Soft Device0Y0\x13\x06\x07*\x86H\xce=\x02\x01\x06\x08*\x86H\xce=\x03\x01\x07\x03B\x00\x04;\xe1\x97\xdds~\x98=\x9f\xb0\xde\t\xe7\\C\xc8\x06]I\xde\x9a%\xe8\x8b\xe2D\x03\x1c\xfe\x10\x88dV\xc3\x0f\x03,\xe1\xb4\x96xWp\xaa1\x9f\x8c9H\x08\n\xdd\x9a3\x16\x9c1\x7f\\!\xaf\x1d\x81-\xa3P0N0\x1d\x06\x03U\x1d\x0e\x04\x16\x04\x14\r\xa8\xbf\x93WN"h\xee\xa6K\x9bc\x18N\x92\x85\xf7\xb1\x9e0\x1f\x06\x03U\x1d#\x04\x180\x16\x80\x14\r\xa8\xbf\x93WN"h\xee\xa6K\x9bc\x18N\x92\x85\xf7\xb1\x9e0\x0c\x06\x03U\x1d\x13\x04\x050\x03\x01\x01\xff0\t\x06\x07*\x86H\xce=\x04\x01\x03H\x000E\x02 \\\x95\x99u\xbb\xceY\xd8Uhn\xc8&\xd9\xf8\xe2\x8d\xb5*h\xbc\x10{\x03\x93\x87\x00~vt\xaf\x7f\x02!\x00\xfad\xf8\xb7>^%_\x16\xd8\xec\x15\xc5\xca\xbad\x88\xeb\xc2\xa5\xdc\x8dt\xb2\xd8m$\xdb\xbc\x80P90F\x02!\x00\xb2\x9d\xe26%\xda\x17\xd9\xa4\xeaa\xf3&\xab\xda\xfa\x18\xbb\x02T\xfe\xfe\x8a\xfe\xd8wJP\x9c\x9c\xa9\xa5\x02!\x00\x8f\xf4\xfe\x1a\x8e\xee"\xab\xc5:\x85\x1c\x88"Yi\xa7<\x1f+\xdf\xfb@\xdb\xff\xef\xf3\x95\xee\x941\xba'''

SAMPLE_SIG_DATA = b'''\x00\x00\x00\x00\x010F\x02!\x00\xf5A\x03x\xbd\x02\x0e\x949\xefI\xbf\xe7\xf3\xd0\x9f\x07,\x81\x9f\x01-\xbax\xff&\xd0Thf\xfb\x9f\x02!\x00\xcelT\xfebq\x0c\x95\xce\xbd_\x852_\xd4\x83j\x98PaY\xea\x1b\xbd\x9beXu9\x1b\xbe\x00'''


class RawRegistrationResponseTest(unittest.TestCase):
    def test_invalid_data(self):
        self.assertRaises(ValueError,
                          u2f.RawRegistrationResponse, b'', b'', b'abc')

    def test_str(self):
        rawresponse = u2f.RawRegistrationResponse(b'', b'', SAMPLE_REG_DATA)
        self.assertTrue(isinstance(str(rawresponse), str))
        self.assertEqual('050445279c', str(rawresponse)[:10])


class RawAuthenticationResponse(unittest.TestCase):
    def test_str(self):
        rawresponse = u2f.RawAuthenticationResponse(b'', b'', SAMPLE_SIG_DATA)
        self.assertTrue(isinstance(str(rawresponse), str))
        self.assertEqual('0000000001', str(rawresponse)[:10])


class U2fV2Test(unittest.TestCase):

    def test_register_fixed_values(self):
        request = {"challenge": "KEzvDDdHwnXtPHIMb0Uh43hgOJ-wQTsdLujGkeg6JxM", "version": "U2F_V2", "appId": "http://localhost:8081"}
        response = {"registrationData": "BQS94xQL46G4vheJPkYSuEteM6Km4-MwgBAu1zZ6MAbjDDgqhYbpHuIhhGOKjedeDd58qqktqOJsby9wMdHGnUtVQD8ISPywVi3J6SaKebCVQdHPu3_zQigRS8LhoDwKT5Ed3tg8AWuNw9XBZEh4doEDxKGuInFazirUw8acOu2qDcEwggIjMIIBDaADAgECAgRyuHt0MAsGCSqGSIb3DQEBCzAPMQ0wCwYDVQQDEwR0ZXN0MB4XDTE1MDkwNDA3MTAyNloXDTE2MDkwMzA3MTAyNlowKjEoMCYGA1UEAxMfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTkyNDY5Mjg1MjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABC37i_h-xmEtGfWnuvj_BmuhtU18MKShNP_vZ7C2WJwj8OHaSLnzAfha14CMUPaKPtRFfP6w9CFGhvEizH33XZKjOzA5MCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS4yMBMGCysGAQQBguUcAgEBBAQDAgQwMAsGCSqGSIb3DQEBCwOCAQEAab7fWlJ-lOR1sqIxawPU5DWZ1b9nQ0QmNNoetPHJ_fJC95r0esRq5axfmGufbNktNWanHww7i9n5WWxSaMTWuJSF0eAXUajo8odYA8nB4_0I6z615MWa9hTU64Pl9HlqkR5ez5jndmJNuAfhaIF4h062Jw051kMo_aENxuLixnybTfJG7Q5KRE00o2MFs5b9L9fzhDtBzv5Z-vGOefuiohowpwnxIA9l0tGqrum9plUdx06K9TqKMRDQ8naosy01rbouA6i5xVjl-tHT3z-r__FYcSZ_dQ5-SCPOh4F0w6T0UwzymQmeqYN3pP-UUgnJ-ihD-uhEWklKNYRy0K0G0jBGAiEA7rbbx2jwC1YGICkZMR07ggKWaHCwFBxNDW3OwhLNNzUCIQCSq0sjGSUnWMQgPEImrmd3tMKcbrjI995rti6UYozqsg", "clientData": "eyJvcmlnaW4iOiAiaHR0cDovL2xvY2FsaG9zdDo4MDgxIiwgImNoYWxsZW5nZSI6ICJLRXp2RERkSHduWHRQSElNYjBVaDQzaGdPSi13UVRzZEx1akdrZWc2SnhNIiwgInR5cCI6ICJuYXZpZ2F0b3IuaWQuZmluaXNoRW5yb2xsbWVudCJ9"}
        u2f.complete_register(request, response)

    def test_authenticate_fixed_values(self):
        device = {'publicKey': 'BBCcnAOknoMgokEGuTdfpNLQ-uylwlKp_xbEW8urjJsXKv9XZSL-V8C2nwcPEckav1mKZFr5K96uAoLtuxOUf-E', 'keyHandle': 'BIarIKfyMqyf4bEI6tOqGInAfHrrQkMA2eyPJlNnInbAG1tXNpdRs48ef92_b1-mfN4VhaTWxo1SGoxT6CIanw', 'appId': 'http://www.example.com/appid'}
        challenge = {'challenge': 'oIeu-nPxx9DcF7L_DCE3kvYox-c4UuvFb8lNG6th10o', 'version': 'U2F_V2', 'keyHandle': 'BIarIKfyMqyf4bEI6tOqGInAfHrrQkMA2eyPJlNnInbAG1tXNpdRs48ef92_b1-mfN4VhaTWxo1SGoxT6CIanw', 'appId': 'http://www.example.com/appid'}
        response = {'keyHandle': 'BIarIKfyMqyf4bEI6tOqGInAfHrrQkMA2eyPJlNnInbAG1tXNpdRs48ef92_b1-mfN4VhaTWxo1SGoxT6CIanw', 'signatureData': 'AAAAAAEwRQIhAJrcBSpaDprFzXmVw60r6x-_gOZ0t-8v7DGiiKmar0SAAiAYKKEX41nWUCLLoKiBYuHYdPP1MPPNQ0cX_JIybPtThA', 'clientData': 'eyJvcmlnaW4iOiAiaHR0cHM6Ly93d3cuZXhhbXBsZS5jb20iLCAiY2hhbGxlbmdlIjogIm9JZXUtblB4eDlEY0Y3TF9EQ0Uza3ZZb3gtYzRVdXZGYjhsTkc2dGgxMG8iLCAidHlwIjogIm5hdmlnYXRvci5pZC5nZXRBc3NlcnRpb24ifQ'}

        assert u2f.verify_authenticate(device, challenge, response)

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
