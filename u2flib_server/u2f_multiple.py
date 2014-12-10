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

import u2f_v2
from u2flib_server.jsapi import RegisterResponse
from u2flib_server.jsobjects import AuthenticateRequestData, RegisterRequestData
from u2flib_server.utils import rand_bytes


def start_register(app_id, devices, challenge=None):
    # RegisterRequest
    register_request = u2f_v2.start_register(app_id, challenge)

    # SignRequest[]
    sign_requests = []
    for dev in devices:
        sign_requests.append(
            start_authenticate(dev.bind_data, 'check-only'))

    return RegisterRequestData(
        registerRequests=[register_request],
        authenticateRequests=sign_requests
    )


def complete_register(request_data, response, valid_facets=None):
    resp = RegisterResponse(response)
    return u2f_v2.complete_register(request_data.getRegisterRequest(response),
                                    resp,
                                    valid_facets)


def start_authenticate(devices, challenge=None):
    sign_requests = []

    for dev in devices:
        sign_request = u2f_v2.start_authenticate(dev,
                                                 challenge or rand_bytes(32))
        sign_requests.append(sign_request)
    return AuthenticateRequestData(authenticateRequests=sign_requests)


def verify_authenticate(devices, request_data, response, valid_facets=None):
    sign_request = request_data.getAuthenticateRequest(response)

    device = next(dev for dev in devices
                  if dev.keyHandle == sign_request.keyHandle)

    return u2f_v2.verify_authenticate(
        device,
        sign_request,
        response,
        valid_facets
    )
