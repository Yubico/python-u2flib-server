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

from u2flib import u2f_v0 as u2f
from base64 import urlsafe_b64decode

BINDING_DER = urlsafe_b64decode(
    "ab3lk0OXHuYB-zTld7lWuDxWGFFCFFmatP2MXBMOvrBmffdwB2P5_qEa1qcAbNNp" +
    "BAMp4DeZm8Kiz6utxjdT5VI3k_jNeR5vHYR5yGRK7KgsF_6-UteXtgRMdKSzXXNX" +
    "WP3kfVbMewCdmNPigSqii8t1sRUqEps9M3z5Yb-XJwHZicYhs-Y-pxX_MrBqK8Rj" +
    "aGuMr_dbufi5BOvaGPWKH-jKv40-aIDRJERqpAbG2ljoMIIBRDCB6qADAgECAgkB" +
    "kYn_____UYMwCgYIKoZIzj0EAwIwGzEZMBcGA1UEAxMQR251YmJ5IEhTTSBDQSAw" +
    "MDAiGA8yMDEyMDYwMTAwMDAwMFoYDzIwNjIwNTMxMjM1OTU5WjAwMRkwFwYDVQQD" +
    "ExBHb29nbGUgR251YmJ5IHYwMRMwEQYDVQQtAwoAAZGJ_____1GDMFkwEwYHKoZI" +
    "zj0CAQYIKoZIzj0DAQcDQgAEKe7yqvUpDUbU2-DkutjIVtuXt9wvSftfhXrOS3uV" +
    "iksUlShw9xhDs5nPludXT_J4SmtvXW92lsuQ_hQi3Z8hhzAKBggqhkjOPQQDAgNJ" +
    "ADBGAiEAtMrqXcYPv58ATthPxPGFIpgcHDAxVcCCdOiJ8_EMWyMCIQD6r7TxC5L0" +
    "dU47CLWvNT94SFvJA-zn6pESZPwWc7ZZjzBFAiBROGadC5ZIfdDhZn7_VJXHYu3-" +
    "7ksCrFqDA2pE_Pu32wIhAKH5z4xx8dLBD7fW-rES3dl18mQ7nL_q09kzmIDMZ3xz"
)


def test_enroll_serialization():
    enroll1 = u2f.enrollment('https://example.com')
    enroll2 = u2f.enrollment_from_der(enroll1.der)

    assert enroll1.ho == enroll2.ho
    assert enroll1.json == enroll2.json
    assert enroll1.der == enroll2.der


def test_binding_serialization():
    binding = u2f.binding_from_der(BINDING_DER)

    assert binding.ho == u2f.H('https://www.example.com'.encode('punycode'))
    assert binding.km == urlsafe_b64decode("ab3lk0OXHuYB-zTld7lWuA==")
    assert binding.hk == urlsafe_b64decode(
        "dbEVKhKbPTN8-WG_lycB2YnGIbPmPqcV_zKwaivEY2hrjK_3W7n4uQTr2hj1ih" +
        "_oyr-NPmiA0SREaqQGxtpY6A==")

    binding2 = u2f.binding_from_der(binding.der)

    assert binding2.km == binding.km
    assert binding2.grm.der == binding.grm.der
    assert binding2.der == binding.der


def test_challenge_serialization():
    binding = u2f.binding_from_der(BINDING_DER)

    challenge1 = binding.make_challenge()
    challenge2 = binding.challenge_from_der(challenge1.der)

    assert challenge1.challenge == challenge2.challenge
    assert challenge1.der == challenge2.der
