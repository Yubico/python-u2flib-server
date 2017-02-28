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


from u2flib_server.model import JSONDict, Transport


class VendorInfo(JSONDict):
    pass


class Selector(JSONDict):
    pass


class DeviceInfo(JSONDict):

    @property
    def selectors(self):
        selectors = self.get('selectors')
        if selectors is None:
            return None
        return [Selector(selector) for selector in selectors]

    @property
    def transports(self):
        transport_int = self.get('transports')
        if transport_int is None:
            return None
        return [t for t in Transport if t.value & transport_int]


class MetadataObject(JSONDict):

    @property
    def vendorInfo(self):
        return VendorInfo(self['vendorInfo'])

    @property
    def devices(self):
        return [DeviceInfo(dev) for dev in self['devices']]


class Attestation(object):
    def __init__(self, trusted, vendor_info=None, device_info=None,
                 cert_transports=None):
        self._trusted = trusted
        self._vendor_info = vendor_info
        self._device_info = device_info

        if device_info.transports is None and cert_transports is None:
            self._transports = None
        else:
            transports = sum(t.value for t in cert_transports or []) | \
                sum(t.value for t in device_info.transports or [])
            self._transports = [t for t in Transport if t.value & transports]

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
