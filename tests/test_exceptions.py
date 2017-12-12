#!/usr/bin/env python3
import unittest

from context import (
    exceptions,
)


NO_COMMON_NAME = """Using configuration from /tmp/devca/openssl.conf
Check that the request matches the signature
Signature ok
The Subject's Distinguished Name is as follows
countryName           :PRINTABLE:'AU'
stateOrProvinceName   :ASN.1 12:'Some-State'
organizationName      :ASN.1 12:'Internet Widgits Pty Ltd'
The commonName field needed to be supplied and was missing"""


class Test(unittest.TestCase):
    def test_no_common_name(self):
        ex = exceptions.get_exception_from_openssl_output(NO_COMMON_NAME)
        self.assertTrue(isinstance(ex, ValueError))

if __name__ == "__main__":
    unittest.main()
