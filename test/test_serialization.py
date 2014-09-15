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

BINDING_JSON = """{"facets": ["https://www.example.com"], "response": "TryFkMQHor1kSwwl-GvGuaU8bHB6Sf41O50iTqESQh2-mDpmExMJU4PrOkJlkjxuKCQwmJ1NQCiaLDru6beCNAUECGoQn9XZtovqnLrLRtyxdxpcJH5xJYL_5sl2le-iQtC4AFHSiOXWDk4y2cIjD9o9n9RpSL_00PWrXPKVIaJ7zUAtf2O5sIcgCadAwoUXTCmB-eEbwFVg6Qa3ohG31ROq0vPSjV17zQI1zmXZ2lWJ-tuvHRI5hPELZ1zFhcmOxGnRMIIBhzCCAS6gAwIBAgIJAJm-6LEMouwcMAkGByqGSM49BAEwITEfMB0GA1UEAwwWWXViaWNvIFUyRiBTb2Z0IERldmljZTAeFw0xMzA3MTcxNDIxMDNaFw0xNjA3MTYxNDIxMDNaMCExHzAdBgNVBAMMFll1YmljbyBVMkYgU29mdCBEZXZpY2UwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ74Zfdc36YPZ-w3gnnXEPIBl1J3pol6IviRAMc_hCIZFbDDwMs4bSWeFdwqjGfjDlICArdmjMWnDF_XCGvHYEto1AwTjAdBgNVHQ4EFgQUDai_k1dOImjupkubYxhOkoX3sZ4wHwYDVR0jBBgwFoAUDai_k1dOImjupkubYxhOkoX3sZ4wDAYDVR0TBAUwAwEB_zAJBgcqhkjOPQQBA0gAMEUCIFyVmXW7zlnYVWhuyCbZ-OKNtSpovBB7A5OHAH52dK9_AiEA-mT4tz5eJV8W2OwVxcq6ZIjrwqXcjXSy2G0k27yAUDkwRQIgJMh6004c1g-p-xI2y9wxVzzkjakceltiIAVcSmY1KpYCIQCfrKNqEZRuSN7JhmoHZSYUbha9Z4IiIyNR9rJYhJjyUw", "appId": "http://www.example.com/appid"}"""


def test_enroll_serialization():
    enroll1 = u2f.enrollment('https://example.com')
    enroll2 = u2f.deserialize_enrollment(enroll1.serialize())

    assert enroll1.app_id == enroll2.app_id
    assert enroll1.facets == enroll2.facets
    assert enroll1.json == enroll2.json
    assert enroll1.serialize() == enroll2.serialize()


def test_binding_serialization():
    binding = u2f.deserialize_binding(BINDING_JSON)

    assert binding.app_id == 'http://www.example.com/appid'
    assert binding.pub_key == ("BAhqEJ/V2baL6py6y0bcsXcaXCR+cSWC/+bJdpXvokL" +\
        "QuABR0ojl1g5OMtnCIw/aPZ/UaUi/9ND1q1zylSGie80=").decode('base64')

    binding2 = u2f.deserialize_binding(binding.serialize())

    assert binding2.pub_key == binding.pub_key
    assert binding2.response.serialize() == binding.response.serialize()
    assert binding2.serialize() == binding.serialize()


def test_challenge_serialization():
    binding = u2f.deserialize_binding(BINDING_JSON)

    challenge1 = binding.make_challenge()
    challenge2 = binding.deserialize_challenge(challenge1.serialize())

    assert challenge1.challenge == challenge2.challenge
    assert challenge1.serialize() == challenge2.serialize()
