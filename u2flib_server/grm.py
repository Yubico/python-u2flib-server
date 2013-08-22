# Copyright (C) 2013 Yubico AB.
# All rights reserved.
# Proprietary code owned by Yubico AB.
# No rights to modifications or redistribution.

__all__ = ['GRM']

from u2flib_server.utils import pub_key_from_der


class GRM(object):
    def __init__(self, data):
        self.data
        #TODO parse DER encoded data
        self.ho = None
        self.kq_der = None
        self.kq = pub_key_from_der(self.kq_der)
        self.hk = None
        self.csr = None
        self.signature = None

    def verify_csr_signature(self):
        raise Exception('Attest signature verification failed!')

    @property
    def der(self):
        # TODO: Recreate DER encoded data.
        return self.data
