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

from u2flib_server.attestation.model import DeviceInfo, Attestation
from u2flib_server.attestation.matchers import DEFAULT_MATCHERS
from u2flib_server.attestation.resolvers import create_resolver
from u2flib_server.model import Transport
from cryptography import x509
from cryptography.hazmat.backends import default_backend


__all__ = ['MetadataProvider']


class MetadataProvider(object):

    def __init__(self, resolver=None, matchers=DEFAULT_MATCHERS):
        if resolver is None:
            resolver = create_resolver()
        self._resolver = resolver
        self._matchers = {}

        for matcher in matchers:
            self.add_matcher(matcher)

    def add_matcher(self, matcher):
        self._matchers[matcher.selector_type] = matcher

    def get_attestation(self, cert):
        if isinstance(cert, bytes):
            cert = x509.load_der_x509_certificate(cert, default_backend())
        metadata = self._resolver.resolve(cert)
        if metadata is not None:
            trusted = True
            vendor_info = metadata.vendorInfo
            device_info = self._lookup_device(metadata, cert)
        else:
            trusted = False
            vendor_info = None
            device_info = DeviceInfo()
        cert_transports = Transport.transports_from_cert(cert)
        return Attestation(trusted, vendor_info, device_info, cert_transports)

    def _lookup_device(self, metadata, cert):
        for device in metadata.devices:
            selectors = device.selectors
            if selectors is None:
                return device
            for selector in selectors:
                matcher = self._matchers.get(selector.type)
                if matcher and matcher.matches(cert, selector.parameters):
                    return device
        return DeviceInfo()
