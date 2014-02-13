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
    enroll2 = u2f.deserialize_enrollment(enroll1.serialize())

    assert enroll1.ho == enroll2.ho
    assert enroll1.json == enroll2.json
    assert enroll1.serialize() == enroll2.serialize()


def test_binding_serialization():
    binding = u2f.deserialize_binding(BINDING_DER)

    assert binding.ho == u2f.H('https://www.example.com'.encode('punycode'))
    assert binding.km == urlsafe_b64decode("ab3lk0OXHuYB-zTld7lWuA==")
    assert binding.hk == urlsafe_b64decode(
        "dbEVKhKbPTN8-WG_lycB2YnGIbPmPqcV_zKwaivEY2hrjK_3W7n4uQTr2hj1ih" +
        "_oyr-NPmiA0SREaqQGxtpY6A==")

    binding2 = u2f.deserialize_binding(binding.serialize())

    assert binding2.km == binding.km
    assert binding2.grm.serialize() == binding.grm.serialize()
    assert binding2.serialize() == binding.serialize()


def test_challenge_serialization():
    binding = u2f.deserialize_binding(BINDING_DER)

    challenge1 = binding.make_challenge()
    challenge2 = binding.deserialize_challenge(challenge1.serialize())

    assert challenge1.challenge == challenge2.challenge
    assert challenge1.serialize() == challenge2.serialize()
