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

from u2flib_server import u2f_v2
from u2flib_server.jsapi import (AuthenticateRequestData, RegisterRequestData,
                                 SignResponse, RegisterResponse)
from u2flib_server.utils import rand_bytes


__all__ = [
    'start_register',
    'complete_register',
    'start_authenticate',
    'verify_authenticate'
]


def start_register(app_id, devices, challenge=None):
    # RegisterRequest
    register_request = u2f_v2.start_register(app_id, challenge)

    # SignRequest[]
    sign_requests = start_authenticate(
        devices,
        'check-only'
    ).authenticateRequests

    return RegisterRequestData(
        registerRequests=[register_request],
        authenticateRequests=sign_requests
    )


def complete_register(request_data, response, valid_facets=None):
    request_data = RegisterRequestData.wrap(request_data)
    response = RegisterResponse.wrap(response)

    return u2f_v2.complete_register(request_data.getRegisterRequest(response),
                                    response,
                                    valid_facets)


def start_authenticate(devices, challenge=None):
    sign_requests = [u2f_v2.start_authenticate(d, challenge or rand_bytes(32))
                     for d in devices]

    return AuthenticateRequestData(authenticateRequests=sign_requests)


def verify_authenticate(devices, request_data, response, valid_facets=None):
    request_data = AuthenticateRequestData.wrap(request_data)
    response = SignResponse.wrap(response)

    sign_request = request_data.getAuthenticateRequest(response)

    device = next(d for d in devices if d.keyHandle == sign_request.keyHandle)

    return u2f_v2.verify_authenticate(
        device,
        sign_request,
        response,
        valid_facets
    )
