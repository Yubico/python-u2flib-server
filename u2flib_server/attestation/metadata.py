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

from u2flib_server.attestation.matchers import DEFAULT_MATCHERS
from u2flib_server.attestation.resolvers import create_resolver

__all__ = ['Attestation', 'MetadataProvider']


class Attestation(object):
    def __init__(self, trusted, vendor_info=None, device_info=None):
        self._trusted = trusted
        self._vendor_info = vendor_info
        self._device_info = device_info

    @property
    def trusted(self):
        return self._trusted

    @property
    def vendor_info(self):
        return self._vendor_info

    @property
    def device_info(self):
        return self._device_info


UNKNOWN_ATTESTATION = Attestation(False)


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
        metadata = self._resolver.resolve(cert)
        if metadata is None:
            return UNKNOWN_ATTESTATION
        vendor_info = metadata.vendorInfo
        device_info = self._lookup_device(metadata, cert)
        return Attestation(True, vendor_info, device_info)

    def _lookup_device(self, metadata, cert):
        for device in metadata.devices:
            selectors = device.selectors
            if selectors is None:
                return device
            for selector in selectors:
                matcher = self._matchers.get(selector.type)
                if matcher and matcher.matches(cert, selector.parameters):
                    return device
        return None
