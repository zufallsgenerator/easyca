#!/usr/bin/env python3
from context import (
    core,
    info,
)
import unittest
import json
from dateutil import (
    tz as du_tz,
    parser as du_parser,
)
import datetime


def get_utcnow_round():
    return datetime.datetime.utcnow().replace(
        tzinfo=du_tz.tzutc(),
        microsecond=0,
    )


class Test(unittest.TestCase):
    def test_create_self_signed_basic(self):
        """Create a self-signed certificate"""
        # Test with rsa:512 for speed purposes, the minimum key length
        res = core.create_self_signed(cn='Acme Industries', newkey='rsa:512')
        self.assertTrue(res.get('success'), res.get('message'))
        self.assertTrue(res.get('cert', '').startswith(
            '-----BEGIN CERTIFICATE-----'))
        self.assertTrue(res.get('key', '').startswith(
            '-----BEGIN PRIVATE KEY-----'))

    def test_create_self_signed(self):
        """Create a self-signed certificate"""
        # Test with rsa:512 for speed purposes, the minimum key length
        now = get_utcnow_round()
        CN = "Acme Corp"
        DAYS = 42
        res = core.create_self_signed(
            cn=CN,
            newkey='rsa:512',
            days=DAYS,
        )
        self.assertTrue(res.get('success'), res.get('message'))
        self.assertTrue(res.get('cert', '').startswith(
            '-----BEGIN CERTIFICATE-----'))

        res_parsed = info.load_x509(res.get('cert'))
        print(json.dumps(res_parsed, indent=4))

        # Verify common name
        self.assertEqual(res_parsed['subject']['CN'], CN)
        self.assertEqual(res_parsed['issuer']['CN'], CN)

        # Verify time delta
        not_before = du_parser.parse(res_parsed.get('notBefore'))
        not_after = du_parser.parse(res_parsed.get('notAfter'))
        self.assertGreaterEqual(not_before, now)
        delta = not_after - not_before
        self.assertEqual(delta.days, DAYS)



#        self.assertTrue(res.get('key', '').startswith(
#            '-----BEGIN PRIVATE KEY-----'))


if __name__ == "__main__":
    unittest.main()
