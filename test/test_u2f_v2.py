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

from u2flib_server import u2f_v2 as u2f
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


def test_authenticate_soft_u2f():
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


def test_wrong_facet():
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
