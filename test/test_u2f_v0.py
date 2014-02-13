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

from u2flib_server import u2f_v0 as u2f
from u2flib_server.soft_u2f_v0 import SoftU2FDevice
from u2flib_server.utils import websafe_encode
from M2Crypto import EC
import json

ORIGIN = 'https://www.example.com'
DATA = """
BBKIEgy97FSqgAyBA+4a+EUiJHOY4NGWx9h9hj39kSoqlDOFdKjGwXUOMkrpz8pJUURAWWCOMcCB
wDAQSttU5s9HBU1veX94KyVFEqjw72Rc/3lyhsQxk8Yg2o3OKiXWEOzaKSQKJ1TU0I46p2y5ZWEz
LHhEHH1agWGs8tE/LmHdMIIBRDCB6qADAgECAgkBkYn/////UYMwCgYIKoZIzj0EAwIwGzEZMBcG
A1UEAxMQR251YmJ5IEhTTSBDQSAwMDAiGA8yMDEyMDYwMTAwMDAwMFoYDzIwNjIwNTMxMjM1OTU5
WjAwMRkwFwYDVQQDExBHb29nbGUgR251YmJ5IHYwMRMwEQYDVQQtAwoAAZGJ/////1GDMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAEHxMC8SFzqcvqg9BtdVQR5YKof7tYUO3c82B+x1mkoSw8s5Ij
Xo1bF8ruGzTltetUhklpYlfw6o77kIRviK1fcjAKBggqhkjOPQQDAgNJADBGAiEAtMrqXcYPv58A
TthPxPGFIpgcHDAxVcCCdOiJ8/EMWyMCIQD6r7TxC5L0dU47CLWvNT94SFvJA+zn6pESZPwWc7ZZ
jzBGAiEA0gdNDBfrrDGqNrnnEhZCrGsf5hn8l4flPO5ZLN7zUmcCIQCE2pZCNQo3Qoq2DVnuPk77
ak2HUYmqZU9ler2WzSXX3gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAA
""".decode('base64')


def test_enroll_static_data():
    enrollment = u2f.enrollment(ORIGIN)
    enroll_request = enrollment.json

    # GNUBBY STUFF
    request = json.loads(enroll_request)
    ys = request['v0'].encode('utf-8')

    dh = EC.gen_params(u2f.CURVE)
    dh.gen_key()
    der = str(dh.pub().get_der())
    yd = websafe_encode(der[-65:])

    km = u2f.P2DES(dh, ys)
    grm = websafe_encode(u2f.E(DATA, km))

    response = {
        "version": "v0",
        "grm": grm,
        "dh": yd
    }
    binding = enrollment.bind(response)
    assert binding


def test_enroll_soft_u2f():
    device = SoftU2FDevice()

    enrollment = u2f.enrollment(ORIGIN)

    response = device.register(enrollment.json)

    binding = enrollment.bind(response)
    assert binding


def test_challenge_soft_u2f():
    device = SoftU2FDevice()
    enrollment = u2f.enrollment(ORIGIN)
    response = device.register(enrollment.json)
    binding = enrollment.bind(response)

    challenge1 = binding.make_challenge()
    challenge2 = binding.make_challenge()

    response2 = device.getAssertion(challenge2.json)
    response1 = device.getAssertion(challenge1.json)

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
