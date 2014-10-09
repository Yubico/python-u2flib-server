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

"""
Example web server providing U2F enrollment and authentication. It can be run
standalone, or by a WSGI container such as Apache with mod_wsgi.

A YubiAuth installation is required to store users and their enrollment data.

Enrollment will overwrite existing users. All users will have a u2f_ prefix
added to their usernames.

Any error will be returned as a stacktrace with a 400 response code.

Note that this is intended for test/demo purposes, not production use!
"""

from yubiauth import YubiAuth
from u2flib_server.u2f_v2 import (start_register, complete_register,
                                  start_authenticate, verify_authenticate)
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
        self.app_id = self.origin
        page = request.path_info_pop()

        # To be able to see what the server considers its origin to be:
        if page == 'origin':
            return self.origin
        elif page is None:
            return json.dumps([self.origin])

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
        enroll = start_register(self.app_id)
        user.attributes['_u2f_enroll_'] = enroll.json
        return enroll.json

    def bind(self, username, password, data):
        user = self._get_user(username, password)
        enroll = user.attributes['_u2f_enroll_']
        binding, cert = complete_register(enroll, data, [self.origin])
        user.attributes['_u2f_binding_'] = binding.json
        user.attributes['_u2f_cert_'] = cert.as_pem()
        return json.dumps({
            'username': username[4:],
            'origin': self.origin,
            'attest_cert': cert.as_pem()
        })

    def sign(self, username, password):
        user = self._get_user(username, password)
        binding = user.attributes['_u2f_binding_']
        challenge = start_authenticate(binding)
        user.attributes['_u2f_challenge_'] = challenge.json
        return challenge.json

    def verify(self, username, password, data):
        user = self._get_user(username, password)
        binding = user.attributes['_u2f_binding_']

        challenge = user.attributes['_u2f_challenge_']
        c, t = verify_authenticate(binding, challenge, data, [self.origin])
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
