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

import json
from u2flib.u2f_v0 import enrollment as enroll_v0
from u2flib.u2f_v1 import enrollment as enroll_v1

VERSIONS = {
    'v0': enroll_v0,
    'v1': enroll_v1
}


class MultiEnroll(object):
    def __init__(self, origin, versions=VERSIONS.keys()):
        self.enrolls = {}
        for version in versions:
            self.enrolls[version] = VERSIONS[version](origin)

    @property
    def json(self):
        data = {}
        for key, enroll in self.enrolls.items():
            data.update(json.loads(enroll.json))
        return json.dumps(data)

    def bind(self, responses):
        if isinstance(responses, basestring):
            responses = json.loads(responses)

        bindings = []

        for response in responses:
            version = response['version']
            if version not in self.enrolls:
                raise ValueError("Unsupported version!")
            bindings.append(self.enrolls[version].bind(response))

        return bindings

    @property
    def der(self):
        # TODO
        return ""

    @classmethod
    def from_der(der):
        # TODO
        return MultiEnroll(None)


enrollment = MultiEnroll.__call__
enrollment_from_der = MultiEnroll.from_der
