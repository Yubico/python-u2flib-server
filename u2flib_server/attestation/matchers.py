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
