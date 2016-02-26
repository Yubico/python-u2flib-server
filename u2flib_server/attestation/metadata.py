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

from u2flib_server.attestation.matchers import DEFAULT_MATCHERS
from u2flib_server.attestation.resolvers import create_resolver
from u2flib_server.jsapi import DeviceInfo
from u2flib_server.yubicommon.compat import byte2int

from cryptography.x509 import ObjectIdentifier, ExtensionNotFound
from enum import IntEnum

__all__ = ['Attestation', 'MetadataProvider', 'Transport']


TRANSPORTS_EXT_OID = ObjectIdentifier('1.3.6.1.4.1.45724.2.1.1')


class Transport(IntEnum):
    BT_CLASSIC = 0x01  # Bluetooth Classic
    BLE = 0x02  # Bluetooth Low Energy
    USB = 0x04
    NFC = 0x08


class Attestation(object):
    def __init__(self, trusted, vendor_info=None, device_info=None,
                 cert_transports=0):
        self._trusted = trusted
        self._vendor_info = vendor_info
        self._device_info = device_info
        self._transports = cert_transports | device_info.transports

    @property
    def trusted(self):
        return self._trusted

    @property
    def vendor_info(self):
        return self._vendor_info

    @property
    def device_info(self):
        return self._device_info

    @property
    def transports(self):
        return self._transports


def get_transports(cert):
    """Parses transport extension from attestation cert.
    As the information is stored as a bitstring, which is a bit unwieldy to work
    with, we convert it into an integer where each bit represents a transport
    flag (as defined in the Transport IntEnum).
    """
    try:
        ext = cert.extensions.get_extension_for_oid(TRANSPORTS_EXT_OID)
        der_bitstring = ext.value.value
        int_bytes = [byte2int(b) for b in der_bitstring[3:]]

        # Mask away unused bits (should already be 0, but make sure)
        unused_bits = byte2int(der_bitstring[2])
        unused_bit_mask = 0xff
        for _ in range(unused_bits):
            unused_bit_mask <<= 1
        int_bytes[-1] &= unused_bit_mask

        # Reverse the bitstring and convert to integer
        transports = 0
        for byte in int_bytes:
            for _ in range(8):
                transports = (transports << 1) | (byte & 1)
                byte >>= 1
        return transports
    except ExtensionNotFound:
        return 0


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
        if metadata is not None:
            trusted = True
            vendor_info = metadata.vendorInfo
            device_info = self._lookup_device(metadata, cert)
        else:
            trusted = False
            vendor_info = None
            device_info = DeviceInfo()
        cert_transports = get_transports(cert)
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
