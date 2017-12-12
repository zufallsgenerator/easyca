#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import datetime
import os
import shutil
import tempfile
import unittest

from context import (
    CA,
    DistinguishedName,
    parser,
)
from dateutil import (
    tz as du_tz,
)

CSR_CN = """-----BEGIN CERTIFICATE REQUEST-----
MIICWzCCAUMCAQAwFjEUMBIGA1UEAxMLZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQCfjTsoNZKRJjDtHM0sJO5va34+R+P0h5c2vr1U
hcJyCn3XYPu3iA2w4ox8licPktlehQ0saEgJclhV+UEnyPbDVfTcQknDaLSXTaUU
+OgJW4GMimEZwycw1HXq73NwJ370Ce5yvM+5QGyfw41XLg6wNOmbu91AYlup1ffq
VmS+pDtrA57DgeCftJLxWJTXPXwOK1iGeTgj7+f5yfxR9IXqgY5lHQ4WrLVLXLBx
Cj3EVMPVtvEGGGuF5t1zkTawLyFz8Qo13tEtK5hq+OBiscTswti+6lByAw7shh7O
EQ5hmQ/6MLERi92ywsyet5t6dVf974zNxMBKGGPZG4h6GpG1AgMBAAGgADANBgkq
hkiG9w0BAQsFAAOCAQEAm04XRfIl27bk4zT4z0iTXHS5VUazVbs2dGVqo88d+cN5
1zirGzuCAlI4qP559bKLrC3yYAwlgQamJfBIjHsV94tshSOC82BO+t9w4juy2jEq
csLyzg3YR/0wOcksL9pcpifaxZxbxXe6p4MqbXMi/CwCc6YUl+AZm7i8oqnpsdTf
GKA7V+ffIUFn0iTPlL54qPuKAQrM09muIiq/RsZNbsQ1Ni6GJ6IEfORUnJ/rAtBs
M36FgMxCfUsfm/tcRTc1G61nw+HdT3PdcqtzM0OQQL6qAQAlu2mz+wMCLSXXixvt
3nPLOIC5rq7mEs9keX8YNUoV3qyQPfAVRLEm1J3RZg==
-----END CERTIFICATE REQUEST-----"""

CSR_SAN = """-----BEGIN CERTIFICATE REQUEST-----
MIICwTCCAakCAQAwLzEaMBgGA1UEChMRQWNtZSBNYWNoaW5lcyBJTkMxETAPBgNV
BAMTCGFjbWUub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwIh4
72xrmNoohlEehND2cCP6laXwRAP25D5L+TK82LVPOzJGPvXDJ/BtA1+0uowThsfq
DYBS3qQnl1Ra1yZa7whJoSpXf41BCyCOvgrYgNNUeqQc/CzssmcHNHMP8GaEkeOM
vTuk5s1yo0ckqRaS3jE+rBkC0Gft1cqCT5XluZJKp1cWZFbATaNLWpBVWDgpVKW9
qa0Ld4FJHoP7hDTxI2oPeTkV/evfOF4rtXdjsZGGQYhlvIYc2d8OmJvLilZu+9FH
k9qr4w7lkgel/wA9GSNP+hQ05j7SI8qd2RRnDLidoaYuYVAnmjQLbXjP0Ea0S+qV
g+Q3XoLcZyUgM9rQtQIDAQABoE0wSwYJKoZIhvcNAQkOMT4wPDA6BgNVHREEMzAx
gghhY21lLm9yZ4IMd3d3LmFjbWUub3JnghFjZG4xLmZhci1hd2F5LmNvbYcEwKg4
ZDANBgkqhkiG9w0BAQsFAAOCAQEAqqYsX9bDBeLFu4oecqLy3ICp1ocTs6sl7MG+
IQBMSQLRzrJ8lbLSJK+nNysEUhKfEM+5ux+7Tv6yVZn38zFTI7mHYlvI/852pTk6
VxLxH1a0SdQF5PjVLgxVOvc7K6bOMHiH4f88P/vawi5v2367WUnHaWRIM8SejVgS
6X5OKa26tsvi2nGIKNXaJK5/YpUkIbehUcPUIFCAhY+2zLFRfyZ/lOZLIyy8AXdI
D3b2JhkAAMG/ECc/Pdpb0JLZFNxid2XnK5/1ZxJuosdkL9MszFt9TfeHQHbxljt1
/HoL3zy0d8ulR4qUq1M1gsVjUIb2NDWjjWgV9JYx1omOmeD5Ng==
-----END CERTIFICATE REQUEST-----"""

CSR_NO_CN = """-----BEGIN CERTIFICATE REQUEST-----
MIICijCCAXICAQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUx
ITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAL8sVBIs0ig1yF5z6FRnKrotnJinrkbHSvno/EYv
POIywOLGWOGiXNDXewlcBKAzdqLhRYhoguYQSmi/F8gM2sIefmq48TH3rJA2HHOB
OUMMg7xmav6vCtFIvjduyAH/GPRBGY/FkRUUq7uTl/65DhktB9VzCzaqumzo7nzF
5O1cF3xCvZC4QL9htMHAyMXgSovXoAnebk+JAmfqMIVDH4+dv2rBc7eg4MJ36EjK
tHtI0a8vtz4aGIXhDdV1NKJUl/2KWhx0iaORz+I8n/56sCJpl2t3fZszLC8HHLDb
WwN54di/pQec3NDctzBbBxRBVf/vnyBnpjVW+peCzqhtap8CAwEAAaAAMA0GCSqG
SIb3DQEBCwUAA4IBAQC+bT8UUv7bTFIpGN6krNo4yZd1MpOvdv1CLuMlVUEMK45i
nrZVGiqz01N1Beo5BRQOUbjXUdouK0jJlkOp2dZHhKMiE7Rhh3SOXxRVUsoKgL6S
IuW/n29G4oZtuPhHhaMV/tWx0whUhtwPwZoI2t25FqP+bphaRqPWRBP7xIHbzcU6
ioJAFlztx4GGc3mM86h2meaKTNIOubCiFozmAE3PC1qS0r+b+CbI3RQnMkACzhS1
XeeQ6MFRYDeSh/iaYOUC1mA0ppZcVIUYOaRVz9etpTTgwqE+7AdIezLJ/OrK6cVp
Sk9moTHXZj1xQnKfoYw1n5rlsGoHkQDbeCYGNoVG
-----END CERTIFICATE REQUEST-----"""


def get_utcnow_round():
    return datetime.datetime.utcnow().replace(
        tzinfo=du_tz.tzutc(),
        microsecond=0,
    )


def get_san_from_extensions(extensions):
    for ext in extensions:
        if ext['name'] == 'subjectAlternativeName':
            return [
                e.strip() for e in ext['str'].split(",")
            ]
    return


class Test(unittest.TestCase):
    def setUp(self):
        self._tempdirs = []
        self._openssl_path = os.environ.get(
            "OPENSSL", self._get_openssl_path())

    def _get_openssl_path(self):
        with os.popen('which openssl') as f:
            return f.read().strip()

    def tearDown(self):
        for path in self._tempdirs:
            try:
                shutil.rmtree(path)
            except:
                pass

    def create_tempdir(self):
        tempdir = tempfile.mkdtemp()
        self._tempdirs.append(tempdir)
        return tempdir

    def init_ca(self):
        ca_path = self.create_tempdir()
        common_name = "Acme Root CA"
        ca = CA(ca_path=ca_path, openssl_path=self._openssl_path)
        res_ca = ca.initialize(
            dn=dict(cn=common_name),
            newkey='rsa:512',
            alt_names=[
                'example.com',
            ],
        )
        self.assertTrue(res_ca.get('success'))
        return ca

    def test_create_ca(self):
        ca_path = self.create_tempdir()
        common_name = "Acme Root CA"
        ca = CA(ca_path=ca_path, openssl_path=self._openssl_path)
        res = ca.initialize(
            dn=dict(cn=common_name),
            newkey='rsa:512',
            alt_names=[
                'acme.com',
                'www.acme.com',
                '192.168.56.100',
                'hello@example.com',
                'http://www.example.com',
            ]
        )
        self.assertTrue(res.get('success'), "Message: {}\nConf: {}\n".format(
            res.get('message'), res.get("conf")))

        res_parsed = parser.get_x509_as_json(
            text=res.get('cert'),
            openssl_path=self._openssl_path
        )

        san = get_san_from_extensions(res_parsed['extensions'])

        self.assertEqual(len(san), 5)
        self.assertEqual(sorted(san), sorted([
            "DNS:acme.com",
            "DNS:www.acme.com",
            "IP Address:192.168.56.100",
            "email:hello@example.com",
            "URI:http://www.example.com"
        ]))

    def test_create_ca_utf8(self):
        ca_path = self.create_tempdir()
        ca = CA(ca_path=ca_path, openssl_path=self._openssl_path)
        res_ca = ca.initialize(
            dn=dict(
                cn='example.com',
                c='se',
                st='Östergötlands Län',
            ),
            newkey='rsa:512',
        )
        self.assertTrue(res_ca.get('success'))
        info = ca.get_info()
        print(info)

        st = info['rootca']['subject']['ST']

        self.assertEqual(st, 'Östergötlands Län')

    def test_create_ca_utf8_higher_codepoint(self):
        ca_path = self.create_tempdir()
        ca = CA(ca_path=ca_path, openssl_path=self._openssl_path)
        res_ca = ca.initialize(
            dn=dict(
                cn='Ragnarr Lođbrok',
                c='no',
                st='Kattegatt',
            ),
            newkey='rsa:512',
        )
        self.assertTrue(res_ca.get('success'))
        info = ca.get_info()

        cn = info['rootca']['subject']['CN']

        self.assertEqual(cn, 'Ragnarr Lođbrok')

    def test_create_ca_and_sign_cert(self):
        """Create a CA and sign certificates with it"""
        ca_path = self.create_tempdir()
        common_name = "Acme Root CA"
        ca = CA(ca_path=ca_path, openssl_path=self._openssl_path)
        res_ca = ca.initialize(
            dn=dict(cn=common_name),
            newkey='rsa:512',
            alt_names=[
                'example.com',
                'www.example.com',
                '192.168.56.100',
                'hello@example.com',
                'http://www.example.com',
            ],
        )
        self.assertTrue(
            res_ca.get('success'), "Message: {}\nConf: {}\n".format(
                res_ca.get('message'), res_ca.get("conf")))

        # CN certificate
        res_cert = ca.sign_request(CSR_CN)
        self.assertTrue(res_cert.get('success'), "Message: {}\n".format(
            res_cert.get('message')))

        res_parsed = parser.get_x509_as_json(
            text=res_cert.get('cert'),
            openssl_path=self._openssl_path)
        self.assertEqual(res_parsed['issuer']['CN'], common_name)
        self.assertEqual(res_parsed['subject']['CN'], 'example.com')

        # SAN certificate
        res_cert_san = ca.sign_request(CSR_SAN)
        self.assertTrue(res_cert_san.get('success'), "Message: {}\n".format(
            res_cert_san.get('message')))

        res_parsed = parser.get_x509_as_json(
            text=res_cert_san.get('cert'),
            openssl_path=self._openssl_path)

        self.assertEqual(res_parsed['issuer']['CN'], common_name)
        self.assertEqual(res_parsed['subject']['O'], 'Acme Machines INC')

        san = get_san_from_extensions(res_parsed['extensions'])
        expected_san = [
            'DNS:acme.org',
            'DNS:cdn1.far-away.com',
            'DNS:www.acme.org',
            'IP Address:192.168.56.100'
        ]
        self.assertEqual(
            sorted(san),
            expected_san
        )

        requests = ca.list_requests()
        self.assertEqual(len(requests), 2)

        certs = ca.list_certificates()
        self.assertTrue(len(certs) > 0)

        for cert in certs:
            cert_res = ca.get_certificate(serial=cert['id'])
            self.assertTrue(cert_res is not None)

    def test_get_csr(self):
        """Create a CA and sign certificates with it"""
        ca_path = self.create_tempdir()
        common_name = "Acme Root CA"
        ca = CA(ca_path=ca_path, openssl_path=self._openssl_path)
        res_ca = ca.initialize(
            dn=dict(cn=common_name),
            newkey='rsa:512',
            alt_names=[
                'example.com',
                'www.example.com',
                '192.168.56.100',
                'hello@example.com',
                'http://www.example.com',
            ],
        )
        self.assertTrue(
            res_ca.get('success'), "Message: {}\nConf: {}\n".format(
                res_ca.get('message'), res_ca.get("conf")))

        # CN certificate
        res_cert = ca.sign_request(CSR_CN)
        self.assertTrue(res_cert.get('success'), "Message: {}\n".format(
            res_cert.get('message')))

        csrs = ca.list_requests()
        self.assertEqual(len(csrs), 1)

        server_csr = ca.get_request(csrs[0]['id'])
        self.assertTrue('subject' in server_csr)
        self.assertEqual(server_csr['subject']['CN'], 'example.com')

    def test_get_csr_san(self):
        """Create a CA and sign certificates with it"""
        ca_path = self.create_tempdir()
        common_name = "Acme Root CA"
        ca = CA(ca_path=ca_path, openssl_path=self._openssl_path)
        res_ca = ca.initialize(
            dn=dict(cn=common_name),
            newkey='rsa:512',
            alt_names=[
                'example.com',
                'www.example.com',
                '192.168.56.100',
                'hello@example.com',
                'http://www.example.com',
            ],
        )
        self.assertTrue(
            res_ca.get('success'), "Message: {}\nConf: {}\n".format(
                res_ca.get('message'), res_ca.get("conf")))

        # SAN certificate
        res_cert_san = ca.sign_request(CSR_SAN)
        self.assertTrue(res_cert_san.get('success'), "Message: {}\n".format(
            res_cert_san.get('message')))

        csrs = ca.list_requests()
        self.assertEqual(len(csrs), 1)

        server_csr = ca.get_request(csrs[0]['id'])
        self.assertTrue('subject' in server_csr)
        self.assertEqual(server_csr['subject']['CN'], 'acme.org')

        res_parsed = parser.get_x509_as_json(
            text=res_cert_san.get('cert'), openssl_path=self._openssl_path)

        self.assertEqual(res_parsed['issuer']['CN'], common_name)
        self.assertEqual(res_parsed['subject']['O'], 'Acme Machines INC')

        san = get_san_from_extensions(res_parsed['extensions'])
        expected_san = [
            'DNS:acme.org',
            'DNS:cdn1.far-away.com',
            'DNS:www.acme.org',
            'IP Address:192.168.56.100'
        ]
        self.assertEqual(
            sorted(san),
            expected_san
        )

        requests = ca.list_requests()
        self.assertEqual(len(requests), 1)

        certs = ca.list_certificates()
        self.assertTrue(len(certs) > 0)

        for cert in certs:
            cert_res = ca.get_certificate(serial=cert['id'])
            self.assertTrue(cert_res is not None)

    def test_sign_csr_no_cn(self):
        ca = self.init_ca()
        caught_error = None
        try:
            ca.sign_request(csr=CSR_NO_CN)
        except Exception as e:
            caught_error = e

        self.assertTrue(caught_error is not None)
        self.assertTrue(isinstance(caught_error, ValueError))
        self.assertIn("missing", str(caught_error).lower())


    def test_distinguished_name(self):
        dn = DistinguishedName(cn="example.com")
        self.assertTrue(dn['cn'], "example.com")

        d = dict(cn='KalleAnka')
        dn = DistinguishedName(**d)
        self.assertEqual(dn['cn'], "KalleAnka")

    def test_certificate_lookup_failure(self):
        """Lookup failure of certificate should raise LookupError."""
        ca = self.init_ca()
        got_lookup_error = False
        try:
            ca.get_certificate('1kl23qwioeu123io')
        except LookupError:
            got_lookup_error = True
        self.assertTrue(got_lookup_error)

    def test_request_lookup_failure(self):
        """Lookup failure of certificate should raise LookupError."""
        ca = self.init_ca()
        got_lookup_error = False
        try:
            ca.get_request('1kl23qwioeu123io')
        except LookupError:
            got_lookup_error = True
        self.assertTrue(got_lookup_error)


if __name__ == "__main__":
    unittest.main()
