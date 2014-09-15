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


from M2Crypto import EC, Rand
from base64 import urlsafe_b64decode, urlsafe_b64encode
from hashlib import sha256
import os

PUB_KEY_DER_PREFIX = "3059301306072a8648ce3d020106082a8648ce3d030107034200" \
    .decode('hex')


def pub_key_from_der(der):
    return EC.pub_key_from_der(PUB_KEY_DER_PREFIX + der)


def websafe_decode(data):
    if isinstance(data, unicode):
        data = data.encode('utf-8')
    data += '=' * (-len(data) % 4)
    return urlsafe_b64decode(data)


def websafe_encode(data):
    return urlsafe_b64encode(data).replace('=', '')


def sha_256(data):
    h = sha256()
    h.update(data)
    return h.digest()


Rand.rand_seed(os.urandom(1024))


def rand_bytes(n_bytes):
    return Rand.rand_bytes(n_bytes)
