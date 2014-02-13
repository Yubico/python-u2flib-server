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


def test_enroll_soft_u2f():
    device = SoftU2FDevice()

    enrollment = u2f.enrollment(APP_ID, FACETS)

    response = device.register(enrollment.json, FACET)

    binding = enrollment.bind(response)
    assert binding


def test_challenge_soft_u2f():
    device = SoftU2FDevice()
    enrollment = u2f.enrollment(APP_ID, FACETS)
    response = device.register(enrollment.json, FACET)
    binding = enrollment.bind(response)

    challenge1 = binding.make_challenge()
    challenge2 = binding.make_challenge()

    response2 = device.getAssertion(challenge2.json, FACET)
    response1 = device.getAssertion(challenge1.json, FACET)

    assert challenge1.validate(response1)
    assert challenge2.validate(response2)

    try:
        challenge1.validate(response2)
    except:
        pass
    else:
        assert False, "Incorrect validation should fail!"

    try:
        challenge2.validate(response1)
    except:
        pass
    else:
        assert False, "Incorrect validation should fail!"


def test_wrong_facet():
    device = SoftU2FDevice()

    enrollment = u2f.enrollment(APP_ID, FACETS)

    response1 = device.register(enrollment.json, "http://wrongfacet.com")

    try:
        binding = enrollment.bind(response1)
    except:
        pass
    else:
        assert False, "Incorrect facet should fail!"

    response2 = device.register(enrollment.json, FACET)
    binding = enrollment.bind(response2)

    challenge = binding.make_challenge()

    response = device.getAssertion(challenge.json, "http://notright.com")

    try:
        challenge.validate(response)
    except:
        pass
    else:
        assert False, "Incorrect facet should fail!"
