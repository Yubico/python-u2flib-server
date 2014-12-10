import unittest
from u2flib_server import u2f_multiple as u2f
from soft_u2f_v2 import SoftU2FDevice

APP_ID = 'http://www.example.com/appid'
FACET = 'https://www.example.com'
FACETS = [FACET]


class MyTestCase(unittest.TestCase):  # TODO: Use Nosetest instead of unittest
    def test_register_soft_u2f(self):
        device, token = self.registerToken()
        assert device

    def test_authenticate_single_soft_u2f(self):
        # Register
        device, token = self.registerToken()

        # Authenticate
        sign_request = u2f.start_authenticate([device])

        response1 = token.getAssertion(
            sign_request.authenticateRequests[0].json,
            FACET
        )

        assert u2f.verify_authenticate([device], sign_request, response1)

    def test_authenticate_multiple_soft_u2f(self):
        # Register
        device1, token1 = self.registerToken()
        device2, token2 = self.registerToken()

        # Authenticate
        auth_request_data = u2f.start_authenticate([device1, device2])

        response = token1.getAssertion(
            auth_request_data.authenticateRequests[0].json,
            FACET
        )

        assert u2f.verify_authenticate([device1, device2],
                                       auth_request_data,
                                       response)

    def registerToken(self):
        token = SoftU2FDevice()
        request_data = u2f.start_register(APP_ID, [])
        response = token.register(request_data.registerRequests[0].json, FACET)
        device, cert = u2f.complete_register(request_data, response)
        return device, token


if __name__ == "__main__":
    unittest.main()