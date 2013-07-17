from yubiauth import YubiAuth
from u2flib.u2f_v0 import enrollment, enrollment_from_der, binding_from_der
from webob.dec import wsgify
from webob import exc
import json
import traceback


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
        self.origin = get_origin(request.environ)
        page = request.path_info_pop()

        # To be able to see what the server considers its origin to be:
        if page == 'origin':
            return self.origin

        with YubiAuth() as auth:
            try:
                username = 'u2f_' + request.params['username']
                password = request.params['password']
                data = request.params.get('data', None)

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
            user = self.auth.get_user(username)
            user.set_password(password)
        except:
            user = self.auth.create_user(username, password)
        enroll = enrollment(self.origin)
        user.attributes['_u2f_enroll_'] = enroll.der.encode('base64')
        return enroll.json

    def bind(self, username, password, data):
        user = self._get_user(username, password)
        enroll_data = user.attributes['_u2f_enroll_'].decode('base64')
        enroll = enrollment_from_der(enroll_data)
        data = json.loads(data)
        if isinstance(data, list):
            if len(data) != 1:
                raise ValueError("Only single device enrollment supported!")
            data = data[0]
        binding = enroll.bind(data)
        user.attributes['_u2f_binding_'] = binding.der.encode('base64')
        return json.dumps({
            'username': username[4:],
            'origin': self.origin,
            'attest_cert': binding.grm.att_cert.as_pem()
        })

    def sign(self, username, password):
        user = self._get_user(username, password)
        binding_data = user.attributes['_u2f_binding_'].decode('base64')
        binding = binding_from_der(binding_data)

        challenge = binding.make_challenge()
        user.attributes['_u2f_challenge_'] = challenge.der.encode('base64')
        return challenge.json

    def verify(self, username, password, data):
        user = self._get_user(username, password)
        binding_data = user.attributes['_u2f_binding_'].decode('base64')
        binding = binding_from_der(binding_data)

        challenge_data = user.attributes['_u2f_challenge_'].decode('base64')
        challenge = binding.challenge_from_der(challenge_data)
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
