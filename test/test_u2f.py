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

from u2flib import u2f
from u2flib.soft_u2f import SoftU2FDevice
from base64 import urlsafe_b64encode, urlsafe_b64decode
from M2Crypto import EC
import json

ORIGIN = 'https://www.example.com'
DATA = "BHQVuSI8ZM6QgykBsguyedZ7gxIXUJEMYJpRHrglnHv3BzON3h5knF-cAw7Zg1G4" +\
    "toW0nO-2MutRrAlnUBph0nw8JvHBv4CVacC2g8POgV81_f9gYAasdPgBKhPUTG6R" +\
    "ddtorMa4894wB_5zFsKSaAo64Fbhm6J9_mwn4i_CLJleMIIBRDCB6qADAgECAgkB" +\
    "kYn_____UYMwCgYIKoZIzj0EAwIwGzEZMBcGA1UEAxMQR251YmJ5IEhTTSBDQSAw" +\
    "MDAiGA8yMDEyMDYwMTAwMDAwMFoYDzIwNjIwNTMxMjM1OTU5WjAwMRkwFwYDVQQD" +\
    "ExBHb29nbGUgR251YmJ5IHYwMRMwEQYDVQQtAwoAAZGJ_____1GDMFkwEwYHKoZI" +\
    "zj0CAQYIKoZIzj0DAQcDQgAEHxMC8SFzqcvqg9BtdVQR5YKof7tYUO3c82B-x1mk" +\
    "oSw8s5IjXo1bF8ruGzTltetUhklpYlfw6o77kIRviK1fcjAKBggqhkjOPQQDAgNJ" +\
    "ADBGAiEAtMrqXcYPv58ATthPxPGFIpgcHDAxVcCCdOiJ8_EMWyMCIQD6r7TxC5L0" +\
    "dU47CLWvNT94SFvJA-zn6pESZPwWc7ZZjzBGAiEAsaOp4Jo4PPGk7RzdGGb8Tub6" +\
    "o_lXBrtnlYufhtJaMkwCIQCsi24WDz9z0CzyQOfZhgOPQBx0Quv20chtpFICVgHK" +\
    "BgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +\
    "AAAAAAAAAAAA"
DATA = urlsafe_b64decode(DATA)


def test_enroll_static_data():
    enrollment = u2f.enrollment()
    enroll_request = enrollment.json

    # GNUBBY STUFF
    request = json.loads(enroll_request)
    ys = request['v0'].encode('utf-8')

    dh = EC.gen_params(u2f.CURVE)
    dh.gen_key()
    der = str(dh.pub().get_der())
    yd = urlsafe_b64encode(der[-65:])

    km = u2f.P2DES(dh, ys)
    grm = urlsafe_b64encode(u2f.encrypt(DATA, km))

    response = {
        "version": "v0",
        "grm": grm,
        "dh": yd
    }
    binding = enrollment.bind(response, ORIGIN)
    assert binding


def test_enroll_soft_u2f():
    device = SoftU2FDevice()

    enrollment = u2f.enrollment()

    response = device.register(enrollment.json)

    binding = enrollment.bind(response, ORIGIN)
    assert binding


def test_challenge_soft_u2f():
    device = SoftU2FDevice()
    enrollment = u2f.enrollment()
    response = device.register(enrollment.json)
    binding = enrollment.bind(response, ORIGIN)

    challenge1 = binding.make_challenge()
    challenge2 = binding.make_challenge()

    response2 = device.getAssertion(challenge2.json)
    response1 = device.getAssertion(challenge1.json)

    assert challenge1.validate(response1)
    assert challenge2.validate(response2)

    try:
    #    challenge1.validate(response2)
        assert False, "Incorrect validation should fail!"
    except:
        pass

    try:
    #    challenge2.validate(response1)
        assert False, "Incorrect validation should fail!"
    except:
        pass
