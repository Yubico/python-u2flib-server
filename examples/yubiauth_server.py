from yubiauth import YubiAuth
from u2flib.u2f_v0 import enrollment, enrollment_from_der, binding_from_der
from base64 import b64encode, b64decode
from webob.dec import wsgify
from webob import exc
import json
import traceback


def load_binding(user):
    binding_data = user.attributes['_u2f_binding_0_'] + \
        user.attributes['_u2f_binding_1_'] + \
        user.attributes['_u2f_binding_2_'] + \
        user.attributes['_u2f_binding_3_'] + \
        user.attributes['_u2f_binding_4_'] + \
        user.attributes['_u2f_binding_5_'] + \
        user.attributes['_u2f_binding_6_']
    return binding_from_der(b64decode(binding_data))


def get_origin(environ):
    if environ.get('HTTP_HOST'):
        host = environ['HTTP_HOST']
    else:
        host = environ['SERVER_NAME']
        if environ['wsgi.url_scheme'] == 'https':
            if environ['SERVER_PORT'] != '443':
                host += ':' + environ['SERVER_PORT']
        else:
            if environ['SERVER_PORT'] != '80':
                host += ':' + environ['SERVER_PORT']

    return '%s://%s' % (environ['wsgi.url_scheme'], host)


class U2FServer(object):
    """
    Very basic server providing a REST API to enroll a U2F device with
    a YubiAuth user, and to perform a sign with the enrolled device.
    Only one device per uses is supported, and only one challenge is valid
    at a time.

    Four calls are provided: enroll, bind, sign and verify. Each of these
    expects username and password parameters, and bind and verify expect a
    third parameter, data, containing the JSON formatted data which is output
    by the U2F browser API upon calling the ENROLL or SIGN commands.
    """
    @wsgify
    def __call__(self, request):
        with YubiAuth() as auth:
            try:
                username = 'u2f_' + request.params['username']
                password = request.params['password']
                data = request.params.get('data', None)
                page = request.path_info_pop()

                self.origin = get_origin(request.environ)
                self.auth = auth
                if page == 'enroll':
                    return self.enroll(username, password)
                elif page == 'bind':
                    return self.bind(username, password, data)
                elif page == 'sign':
                    return self.sign(username, password)
                elif page == 'verify':
                    return self.verify(username, password, data)
                else:
                    raise exc.HTTPNotFound()
            except Exception:
                return exc.HTTPBadRequest(comment=traceback.format_exc())

    def enroll(self, username, password):
        try:
            user = self._get_user(username, password)
            user.set_password(password)
        except:
            user = self.auth.create_user(username, password)
        enroll = enrollment(self.origin)
        enroll_data = b64encode(enroll.der)
        user.attributes['_u2f_enroll_0_'] = enroll_data[:128]
        user.attributes['_u2f_enroll_1_'] = enroll_data[128:]
        return enroll.json

    def bind(self, username, password, data):
        user = self._get_user(username, password)
        enroll_data = user.attributes['_u2f_enroll_0_'] + \
            user.attributes['_u2f_enroll_1_']
        enroll = enrollment_from_der(b64decode(enroll_data))
        binding = enroll.bind(data)
        binding_data = b64encode(binding.der)
        # YubiAuth needs to be able to store blobs, srsly.
        user.attributes['_u2f_binding_0_'] = binding_data[:128]
        user.attributes['_u2f_binding_1_'] = binding_data[128:256]
        user.attributes['_u2f_binding_2_'] = binding_data[256:384]
        user.attributes['_u2f_binding_3_'] = binding_data[384:512]
        user.attributes['_u2f_binding_4_'] = binding_data[512:640]
        user.attributes['_u2f_binding_5_'] = binding_data[640:768]
        user.attributes['_u2f_binding_6_'] = binding_data[768:]
        return json.dumps({
            'username': username[4:],
            'origin': self.origin,
        })

    def sign(self, username, password):
        user = self._get_user(username, password)
        binding = load_binding(user)
        challenge = binding.make_challenge()
        user.attributes['_u2f_challenge_'] = b64encode(challenge.der)
        return challenge.json

    def verify(self, username, password, data):
        user = self._get_user(username, password)
        binding = load_binding(user)

        challenge = binding.challenge_from_der(
            b64decode(user.attributes['_u2f_challenge_']))
        c, t = challenge.validate(data)
        return json.dumps({
            'touch': t,
            'counter': c
        })

    def _get_user(self, username, password):
        user = self.auth.get_user(username)
        if not user.validate_password(password):
            raise ValueError('Invalid password!')
        return user

application = U2FServer()

if __name__ == '__main__':
    from wsgiref.simple_server import make_server
    httpd = make_server('0.0.0.0', 8081, application)
    httpd.serve_forever()
