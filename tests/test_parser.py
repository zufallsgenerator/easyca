#!/usr/bin/env python3
import unittest

from context import (
    parser,
)


class Test(unittest.TestCase):
    def test_transform_distinguished_name_1_1_0(self):
        """Parse DN output for openssl 1.1.0"""
        text = "CN = example.com, O = Acme Corp"
        dn = parser.transform_distinguished_name(text)
        self.assertEqual(dn.get('CN'), 'example.com')
        self.assertEqual(dn.get('O'), 'Acme Corp')

    def test_transform_distinguished_name_1_0_2(self):
        """Parse DN output for openssl 1.0.2"""
        text = " /O=Acme Corp/CN=example.com"
        dn = parser.transform_distinguished_name(text)
        self.assertEqual(dn.get('CN'), 'example.com')
        self.assertEqual(dn.get('O'), 'Acme Corp')

    def test_decode_utf8(self):
        s = "\\xC3\\x96sterg\\xC3\\xB6tlands L\\xC3\\xA4n"
        ret = parser.decode_hex_utf8(s)
        self.assertEqual(ret, "Östergötlands Län")

    def test_decode_utf8_no_x(self):
        """Test decoding openssl versions 1.1.0"""
        s = '\\C3\\96sterg\\C3\\B6tlands L\\C3\\A4n'
        ret = parser.decode_hex_utf8(s)
        self.assertEqual(ret, "Östergötlands Län")

if __name__ == "__main__":
    unittest.main()
