from u2flib_server import u2f_multiple as u2f
from soft_u2f_v2 import SoftU2FDevice

APP_ID = 'http://www.example.com/appid'
FACET = 'https://www.example.com'
FACETS = [FACET]


def test_register_soft_u2f():
    token = SoftU2FDevice()

    request = u2f.start_register(APP_ID)
    response = token.register(request.json, FACET)

    device, cert = u2f.complete_register(request, response)
    assert device
