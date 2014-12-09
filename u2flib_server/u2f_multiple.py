import u2f_v2
from u2flib_server.jsapi import RegisterResponse
from u2flib_server.jsobjects import AuthenticateRequestData, RegisterRequestData, RegisterResponseData
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


# TODO: Create something similar to java-u2flib-server's RegisterRequestData.getRegisterRequests(), instead of request_data.registerRequests[0]
def complete_register(request_data, response, valid_facets=None):
    resp = RegisterResponse(response)
    return u2f_v2.complete_register(request_data.registerRequests[0], resp, valid_facets)


def start_authenticate(devices, challenge=None):
    sign_requests = []
    challenge = challenge or rand_bytes(32)
    for dev in devices.items():
        challenge = start_authenticate(dev.bind_data, challenge)
        sign_requests.append(challenge)
    return AuthenticateRequestData(authenticateRequests=sign_requests)