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
