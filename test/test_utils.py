# coding=utf-8

import unittest

from u2flib_server.utils import websafe_encode, websafe_decode


class TestWebSafe(unittest.TestCase):
    # Base64 vectors adapted from https://tools.ietf.org/html/rfc4648#section-10

    def test_websafe_decode(self):
        self.assertEqual(websafe_decode(b''), b'')
        self.assertEqual(websafe_decode(b'Zg'), b'f')
        self.assertEqual(websafe_decode(b'Zm8'), b'fo')
        self.assertEqual(websafe_decode(b'Zm9v'), b'foo')
        self.assertEqual(websafe_decode(b'Zm9vYg'), b'foob')
        self.assertEqual(websafe_decode(b'Zm9vYmE'), b'fooba')
        self.assertEqual(websafe_decode(b'Zm9vYmFy'), b'foobar')

    def test_websafe_decode_unicode(self):
        self.assertEqual(websafe_decode(u''), b'')
        self.assertEqual(websafe_decode(u'Zm9vYmFy'), b'foobar')

    def test_websafe_encode(self):
        self.assertEqual(websafe_encode(b''), u'')
        self.assertEqual(websafe_encode(b'f'), u'Zg')
        self.assertEqual(websafe_encode(b'fo'), u'Zm8')
        self.assertEqual(websafe_encode(b'foo'), u'Zm9v')
        self.assertEqual(websafe_encode(b'foob'), u'Zm9vYg')
        self.assertEqual(websafe_encode(b'fooba'), u'Zm9vYmE')
        self.assertEqual(websafe_encode(b'foobar'), u'Zm9vYmFy')

    def test_websafe_encode_unicode(self):
        self.assertEqual(websafe_encode(u''), u'')
        self.assertEqual(websafe_encode(u'foobar'), u'Zm9vYmFy')
