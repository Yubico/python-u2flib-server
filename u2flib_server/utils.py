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


from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from base64 import urlsafe_b64decode, urlsafe_b64encode
import six
import re


BASE64URL = re.compile(br'^[-_a-zA-Z0-9]*=*$')


def websafe_decode(data):
    if isinstance(data, six.text_type):
        data = data.encode('ascii')
    if not BASE64URL.match(data):
        raise ValueError('Invalid character(s)')
    data += b'=' * (-len(data) % 4)
    return urlsafe_b64decode(data)


def websafe_encode(data):
    if isinstance(data, six.text_type):
        data = data.encode('ascii')
    return urlsafe_b64encode(data).replace(b'=', b'').decode('ascii')


def sha_256(data):
    h = hashes.Hash(hashes.SHA256(), default_backend())
    h.update(data)
    return h.finalize()
