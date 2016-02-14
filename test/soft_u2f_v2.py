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

from u2flib_server.utils import (websafe_encode, websafe_decode,
                                 sha_256 as H, rand_bytes)
from u2flib_server.jsapi import (RegisterRequest, RegisterResponse,
                                 SignRequest, SignResponse, ClientData)
import struct

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import hashes

CURVE = ec.SECP256R1

CERT = """
MIIBhzCCAS6gAwIBAgIJAJm+6LEMouwcMAkGByqGSM49BAEwITEfMB0GA1UEAwwW
WXViaWNvIFUyRiBTb2Z0IERldmljZTAeFw0xMzA3MTcxNDIxMDNaFw0xNjA3MTYx
NDIxMDNaMCExHzAdBgNVBAMMFll1YmljbyBVMkYgU29mdCBEZXZpY2UwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAAQ74Zfdc36YPZ+w3gnnXEPIBl1J3pol6IviRAMc
/hCIZFbDDwMs4bSWeFdwqjGfjDlICArdmjMWnDF/XCGvHYEto1AwTjAdBgNVHQ4E
FgQUDai/k1dOImjupkubYxhOkoX3sZ4wHwYDVR0jBBgwFoAUDai/k1dOImjupkub
YxhOkoX3sZ4wDAYDVR0TBAUwAwEB/zAJBgcqhkjOPQQBA0gAMEUCIFyVmXW7zlnY
VWhuyCbZ+OKNtSpovBB7A5OHAH52dK9/AiEA+mT4tz5eJV8W2OwVxcq6ZIjrwqXc
jXSy2G0k27yAUDk=
""".decode('base64')

CERT_PRIV = """
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMyk3gKcDg5lsYdl48fZoIFORhAc9cQxmn2Whv/+ya+2oAoGCCqGSM49
AwEHoUQDQgAEO+GX3XN+mD2fsN4J51xDyAZdSd6aJeiL4kQDHP4QiGRWww8DLOG0
lnhXcKoxn4w5SAgK3ZozFpwxf1whrx2BLQ==
-----END EC PRIVATE KEY-----
"""


class SoftU2FDevice(object):

    """
    This simulates the U2F browser API with a soft U2F device connected.
    It can be used for testing.
    """
    def __init__(self):
        self.keys = {}
        self.counter = 0

    def register(self, request, facet="https://www.example.com"):
        """
        RegisterRequest = {
            "version": "U2F_V2",
            "challenge": string, //b64 encoded challenge
            "appId": string, //app_id
        }
        """

        if not isinstance(request, RegisterRequest):
            request = RegisterRequest(request)

        if request.version != "U2F_V2":
            raise ValueError("Unsupported U2F version: %s" % request.version)

        # Client data
        client_data = ClientData(
            typ='navigator.id.finishEnrollment',
            challenge=request['challenge'],
            origin=facet
        )
        client_data = client_data.json
        client_param = H(client_data)

        # ECC key generation
        priv_key = ec.generate_private_key(CURVE, default_backend())
        pub_key = priv_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        pub_key = str(pub_key)[-65:]

        # Store
        key_handle = rand_bytes(64)
        app_param = request.appParam
        self.keys[key_handle] = (priv_key, app_param)

        # Attestation signature
        cert_priv = load_pem_private_key(CERT_PRIV, password=None, backend=default_backend())
        cert = CERT
        data = chr(0x00) + app_param + client_param + key_handle + pub_key
        signer = cert_priv.signer(ec.ECDSA(hashes.SHA256()))
        signer.update(data)
        signature = signer.finalize()

        raw_response = (chr(0x05) + pub_key + chr(len(key_handle)) +
                        key_handle + cert + signature)

        return RegisterResponse(
            registrationData=websafe_encode(raw_response),
            clientData=websafe_encode(client_data),
        )

    def getAssertion(self, request, facet="https://www.example.com",
                     touch=False):
        """
        signData = {
            'version': "U2F_V2",
            'challenge': websafe_encode(self.challenge),
            'appId': self.binding.app_id,
            'keyHandle': websafe_encode(self.binding.key_handle),
        }
        """

        if not isinstance(request, SignRequest):
            request = SignRequest(request)

        if request.version != "U2F_V2":
            raise ValueError("Unsupported U2F version: %s" % request.version)

        key_handle = websafe_decode(request.keyHandle)
        if key_handle not in self.keys:
            raise ValueError("Unknown key handle!")

        # Client data
        client_data = ClientData(
            typ="navigator.id.getAssertion",
            challenge=request['challenge'],
            origin=facet
        )
        client_data = client_data.json
        client_param = H(client_data)

        # Unwrap:
        priv_key, app_param = self.keys[key_handle]

        # Increment counter
        self.counter += 1

        # Create signature
        touch = chr(1 if touch else 0)
        counter = struct.pack('>I', self.counter)

        digest = H(app_param + touch + counter + client_param)
        signer = priv_key.signer(ec.ECDSA(hashes.SHA256()))
        signer.update(digest)
        signature = signer.finalize()
        raw_response = touch + counter + signature

        return SignResponse(
            clientData=websafe_encode(client_data),
            signatureData=websafe_encode(raw_response),
            keyHandle=request.keyHandle
        )
