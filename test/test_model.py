from u2flib_server.utils import websafe_decode
from u2flib_server.model import (JSONDict, RegistrationData, SignatureData,
                                 U2fRegisterRequest, U2fSignRequest)
from binascii import b2a_hex
import unittest


SAMPLE_REG_DATA = websafe_decode(
    'BQRFJ5xApW6uBsuSJ_FgUcL-seKecha71q8evgqfQwc5QuqQhv4qJoL3KpSUKX1T6XVJEqyOkn'
    'Ok397y2Rh5m_zkQD9wrlgMW9EGOGmBQ0lKIa79vcQl2tMF7hlhNjIGrJHw7Rqg8wbnKWSvQjs5'
    'ytK3s3X9YRuNcY3ht5pJYZbGa-4wggGHMIIBLqADAgECAgkAmb7osQyi7BwwCQYHKoZIzj0EAT'
    'AhMR8wHQYDVQQDDBZZdWJpY28gVTJGIFNvZnQgRGV2aWNlMB4XDTEzMDcxNzE0MjEwM1oXDTE2'
    'MDcxNjE0MjEwM1owITEfMB0GA1UEAwwWWXViaWNvIFUyRiBTb2Z0IERldmljZTBZMBMGByqGSM'
    '49AgEGCCqGSM49AwEHA0IABDvhl91zfpg9n7DeCedcQ8gGXUnemiXoi-JEAxz-EIhkVsMPAyzh'
    'tJZ4V3CqMZ-MOUgICt2aMxacMX9cIa8dgS2jUDBOMB0GA1UdDgQWBBQNqL-TV04iaO6mS5tjGE'
    '6ShfexnjAfBgNVHSMEGDAWgBQNqL-TV04iaO6mS5tjGE6ShfexnjAMBgNVHRMEBTADAQH_MAkG'
    'ByqGSM49BAEDSAAwRQIgXJWZdbvOWdhVaG7IJtn44o21Kmi8EHsDk4cAfnZ0r38CIQD6ZPi3Pl'
    '4lXxbY7BXFyrpkiOvCpdyNdLLYbSTbvIBQOTBGAiEAsp3iNiXaF9mk6mHzJqva-hi7AlT-_or-'
    '2HdKUJycqaUCIQCP9P4aju4iq8U6hRyIIllppzwfK9_7QNv_7_OV7pQxug'
)
SAMPLE_REG_DATA_NEEDS_FIX = websafe_decode(
    'BQQR2Q82wJ9RLOcH5TvQvve7LrBnDp0YiCSDxKPiHsg_AY1b70GK-dcCt-HqCkqJZikAXL4zLY'
    'CsKmucc1xna99BQAMOcuxXOpiG-MJIB3zUpvT1hO2v18nBYsRRFjRPIStBxFyh6PMMjA10aZFf'
    '68_EFpgc_CAfEiEqr5L41anLJ3EwggIcMIIBBqADAgECAgQ4Zt91MAsGCSqGSIb3DQEBCzAuMS'
    'wwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEw'
    'MDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowKzEpMCcGA1UEAwwgWXViaWNvIFUyRiBFRSBTZXJpYW'
    'wgMTM4MzExNjc4NjEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ3jfx0DHOblHJO09Ujubh2'
    'gQZWwT3ob6-uzzjZD1XiyAob_gsw3FOzXefQRblty48r-U-o4LkDFjx_btwuSHtxoxIwEDAOBg'
    'orBgEEAYLECgEBBAAwCwYJKoZIhvcNAQELA4IBAQIaR2TKAInPkq24f6hIU45yzD79uzR5KUME'
    'e4IWqTm69METVio0W2FHWXlpeUe85nGqanwGeW7U67G4_WAnGbcd6zz2QumNsdlmb_AebbdPRa'
    '95Z8BG1ub_S04JoxQYNLaa8WRlzN7POgqAnAqkmnsZQ_W9Tj2uO9zP3mpxOkkmnqz7P5zt4Lp5'
    'xrv7p15hGOIPD5V-ph7tUmiCJsq0LfeRA36X7aXi32Ap0rt_wyfnRef59YYr7SmwaMuXKjbIZS'
    'LesscZZTMzXd-uuLb6DbUCasqEVBkGGqTRfAcOmPov1nHUrNDCkOR0obR4PsJG4PiamIfApNeo'
    'XGYpGbok6nucMEUCIQCCL2jamBxyJQ6ktxgJVNFRKf4pUHvlvFgyXTQ6NOYlAwIgSQ1TB64V25'
    'deHKak1UEZA2AbkR9znO2XJKd93v1BY9Y'
)

SAMPLE_SIG_DATA = websafe_decode(
    'AAAAAAEwRgIhAPVBA3i9Ag6UOe9Jv-fz0J8HLIGfAS26eP8m0FRoZvufAiEAzmxU_mJxDJXOvV'
    '-FMl_Ug2qYUGFZ6hu9m2VYdTkbvgA'
)


class RegistrationDataTest(unittest.TestCase):
    def test_invalid_data(self):
        self.assertRaises(ValueError, RegistrationData, b'abc')

    def test_str(self):
        rawresponse = RegistrationData(SAMPLE_REG_DATA)
        self.assertEqual(b'050445279c', b2a_hex(rawresponse.bytes)[:10])
        self.assertEqual(SAMPLE_REG_DATA, rawresponse.bytes)

    def test_str_needs_fix(self):
        rawresponse = RegistrationData(SAMPLE_REG_DATA_NEEDS_FIX)
        self.assertEqual(b'050411d90f', b2a_hex(rawresponse.bytes)[:10])
        self.assertNotEqual(SAMPLE_REG_DATA_NEEDS_FIX, rawresponse.bytes)


class SignatureDataTest(unittest.TestCase):
    def test_str(self):
        rawresponse = SignatureData(SAMPLE_SIG_DATA)
        self.assertEqual(b'0000000001', b2a_hex(rawresponse.bytes)[:10])
        self.assertEqual(SAMPLE_SIG_DATA, rawresponse.bytes)


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

    def test_create_from_list(self):
        self.assertEqual({}, JSONDict([]))
        self.assertEqual({'a': 1, 'b': 2}, JSONDict([('a', 1), ('b', 2)]))

    def test_create_wrong_nargs(self):
        self.assertRaises(TypeError, JSONDict, {}, {})
        self.assertRaises(TypeError, JSONDict, {'a': 1}, {'b': 2})

    def test_json(self):
        self.assertEqual('{}', JSONDict().json)
        self.assertEqual('{"a": 1}', JSONDict(a=1).json)

    def test_wrap(self):
        self.assertTrue(isinstance(JSONDict.wrap({}), JSONDict))
        x = JSONDict()
        self.assertTrue(x is JSONDict.wrap(x))

    def test_getattr_unknown(self):
        self.assertRaises(AttributeError, lambda: JSONDict().foo)

    def test_getattr(self):
        self.assertEqual(1, JSONDict(a=1).a)

    def test_required_fields(self):
        class Foo(JSONDict):
            _required_fields = ['foo', 'bar']

        Foo({'foo': 1, 'bar': 2})
        self.assertRaises(ValueError, Foo, {'foo': 1})
        self.assertRaises(ValueError, Foo, {'bar': 1})
        self.assertRaises(ValueError, Foo)


class U2fRegisterRequestTest(unittest.TestCase):
    def test_u2f_register_request(self):
        challenge = "Jtb6wLXjMHN67fV1BVNivz-qnAnD8OOqFju49RDBJro"
        req = U2fRegisterRequest.create(
            'https://example.com',
            [],
            websafe_decode(challenge)
        )

        self.assertEqual(U2fRegisterRequest.wrap({
            "registeredKeys": [],
            "appId": "https://example.com",
            "registerRequests": [{
                "version": "U2F_V2",
                "challenge": "Jtb6wLXjMHN67fV1BVNivz-qnAnD8OOqFju49RDBJro"
            }]
        }), req)

        self.assertEqual(U2fRegisterRequest.wrap(req.json), req)

        self.assertEqual(
            websafe_decode('EAaArVRs5qV39C9S3zO0z9ynVoWeZkuNfeMpsVDQnOk'),
            req.applicationParameter
        )
        self.assertEqual([], req.registeredKeys)
        self.assertEqual(1, len(req.registerRequests))

        reg_req = req.get_request('U2F_V2')
        self.assertEqual(reg_req.challenge, websafe_decode(challenge))
        self.assertEqual(reg_req.version, 'U2F_V2')


class U2fSignRequestTest(unittest.TestCase):
    def test_missing_keys(self):
        self.assertRaises(ValueError, U2fSignRequest.wrap, {
            "appId": "https://example.com",
            "challenge": "0000",
            "registeredKeys": []
        })

    def test_u2f_sign_request(self):
        challenge = "Jtb6wLXjMHN67fV1BVNivz-qnAnD8OOqFju49RDBJro"
        req = U2fSignRequest.wrap(
            {
                "appId": "https://example.com",
                "registeredKeys": [{
                    "publicKey": "BBCcnAOknoMgokEGuTdfpNLQ-uylwlKp_xbEW8urjJsXK"
                    "v9XZSL-V8C2nwcPEckav1mKZFr5K96uAoLtuxOUf-E",
                    "version": "U2F_V2",
                    "keyHandle": "BIarIKfyMqyf4bEI6tOqGInAfHrrQkMA2eyPJlNnInbAG"
                    "1tXNpdRs48ef92_b1-mfN4VhaTWxo1SGoxT6CIanw"
                }],
                "challenge": challenge
             }
        )
        self.assertEqual(U2fSignRequest.wrap(req.json), req)
        self.assertEqual(
            req.applicationParameter,
            websafe_decode('EAaArVRs5qV39C9S3zO0z9ynVoWeZkuNfeMpsVDQnOk')
        )
        self.assertEqual(req.challenge, websafe_decode(challenge))
