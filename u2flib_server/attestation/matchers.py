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

__all__ = [
    'DeviceMatcher',
    'FingerprintMatcher',
    'ExtensionMatcher',
    'DEFAULT_MATCHERS'
]


class DeviceMatcher(object):
    selector_type = None

    def matches(self, certificate, parameters=None):
        raise NotImplementedError


class FingerprintMatcher(DeviceMatcher):
    selector_type = 'fingerprint'

    def matches(self, certificate, parameters=[]):
        fingerprints = map(lambda s: s.lower(), parameters)
        return certificate.get_fingerprint('sha1').lower() in fingerprints


# This is needed since older versions of M2Crypto don't have a way of getting
# extensions by their OID.
def get_ext_by_oid(cert, oid):
    from pyasn1.codec.der import decoder
    from pyasn1_modules import rfc2459
    cert, _ = decoder.decode(cert.as_der(), asn1Spec=rfc2459.Certificate())
    for ext in cert['tbsCertificate']['extensions']:
        if ext['extnID'].prettyPrint() == oid:
            return decoder.decode(ext['extnValue'])[0].asOctets()
    return None


class ExtensionMatcher(DeviceMatcher):
    selector_type = 'x509Extension'

    def matches(self, certificate, parameters={}):
        key = parameters.get('key')
        match_value = parameters.get('value')
        extension_value = get_ext_by_oid(certificate, key)
        if extension_value is not None:
            if match_value is None or match_value == extension_value:
                return True
        return False


DEFAULT_MATCHERS = [
    FingerprintMatcher(),
    ExtensionMatcher()
]
