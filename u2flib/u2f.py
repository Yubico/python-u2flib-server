# Copyright (C) 2013 Yubico AB.
# All rights reserved.
# Proprietary code owned by Yubico AB.
# No rights to modifications or redistribution.

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
        for enroll in self.enrolls.values():
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
