from u2f_v2 import start_authenticate, start_register
from u2flib_server.jsobjects import AuthenticateRequestData, RegisterRequestData
from u2flib_server.utils import rand_bytes


def start_register(app_id, devices, challenge=None):
    # RegisterRequest
    register_request = start_register(app_id, challenge)

    # SignRequest[]
    sign_requests = []
    for dev in devices:
        sign_requests.append(
            start_authenticate(dev.bind_data, 'check-only'))

    return RegisterRequestData(
        registerRequests=[register_request],
        authenticateRequests=sign_requests
    )


def start_authenticate(devices, challenge=None):
    sign_requests = []
    challenge = challenge or rand_bytes(32)
    for dev in devices.items():
        challenge = start_authenticate(dev.bind_data, challenge)
        sign_requests.append(challenge)
    return AuthenticateRequestData(authenticateRequests=sign_requests)