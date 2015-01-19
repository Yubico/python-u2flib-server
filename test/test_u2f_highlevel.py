#    Copyright (C) 2014  Yubico AB
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

from u2flib_server import u2f
from soft_u2f_v2 import SoftU2FDevice

APP_ID = 'http://www.example.com/appid'
FACET = 'https://www.example.com'
FACETS = [FACET]


def test_register_soft_u2f():
    device, token = register_token()
    assert device


def test_authenticate_single_soft_u2f():
    # Register
    device, token = register_token()

    # Authenticate
    sign_request = u2f.start_authenticate([device])

    response1 = token.getAssertion(
        sign_request.authenticateRequests[0].json,
        FACET
    )

    assert u2f.verify_authenticate([device], sign_request, response1)


def test_authenticate_multiple_soft_u2f():
    # Register
    device1, token1 = register_token()
    device2, token2 = register_token()

    # Authenticate
    auth_request_data = u2f.start_authenticate([device1, device2])

    response = token1.getAssertion(
        auth_request_data.authenticateRequests[0].json,
        FACET
    )

    assert u2f.verify_authenticate([device1, device2],
                                   auth_request_data,
                                   response)


def register_token():
    token = SoftU2FDevice()
    request_data = u2f.start_register(APP_ID, [])
    response = token.register(request_data.registerRequests[0].json, FACET)
    device, cert = u2f.complete_register(request_data, response)
    return device, token
