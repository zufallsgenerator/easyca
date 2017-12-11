#!/usr/bin/env python3
from context import (
    core,
    parser,
)
import unittest
import json
from dateutil import (
    tz as du_tz,
    parser as du_parser,
)
import datetime
import tempfile
import shutil
import os


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

SIGNED_SAN = """-----BEGIN CERTIFICATE-----
MIIDTDCCAjSgAwIBAgIJAPKF1aFIHOdxMA0GCSqGSIb3DQEBCwUAMA8xDTALBgNV
BAMMBE15Q0EwHhcNMTcxMjA2MDczMTM3WhcNMTgwMzA2MDczMTM3WjAvMRowGAYD
VQQKExFBY21lIE1hY2hpbmVzIElOQzERMA8GA1UEAxMIYWNtZS5vcmcwggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDAiHjvbGuY2iiGUR6E0PZwI/qVpfBE
A/bkPkv5MrzYtU87MkY+9cMn8G0DX7S6jBOGx+oNgFLepCeXVFrXJlrvCEmhKld/
jUELII6+CtiA01R6pBz8LOyyZwc0cw/wZoSR44y9O6TmzXKjRySpFpLeMT6sGQLQ
Z+3VyoJPleW5kkqnVxZkVsBNo0takFVYOClUpb2prQt3gUkeg/uENPEjag95ORX9
6984Xiu1d2OxkYZBiGW8hhzZ3w6Ym8uKVm770UeT2qvjDuWSB6X/AD0ZI0/6FDTm
PtIjyp3ZFGcMuJ2hpi5hUCeaNAtteM/QRrRL6pWD5DdegtxnJSAz2tC1AgMBAAGj
gYowgYcwCQYDVR0TBAIwADAdBgNVHQ4EFgQU6dp0MUEyqCHbJAe6zCZGYdLBlgIw
HwYDVR0jBBgwFoAUboY0BA4M28nYzfBcWUYhiAtnVwcwOgYDVR0RBDMwMYIIYWNt
ZS5vcmeCDHd3dy5hY21lLm9yZ4IRY2RuMS5mYXItYXdheS5jb22HBMCoOGQwDQYJ
KoZIhvcNAQELBQADggEBADmbxTonhGvN+DpFuzSNleFgMGy+GA8uC3S6hzGHU0op
9HmEDPDMh33t7sKM4YmsWsUTIndeS2xmYPDn7i6LKjNwlEflAZppWfF01G2RDJmO
bqXulA2g528pneiRjuJVF//sMq95kBpyNvkwUtqP6E35UaBaM891Qy7+m/+vriIk
y8OqjeXlxG1pSBz5hlBedgJEfujUIuy7DpMArn17U5edba9B3fCPmaUyKaff0cS8
xrTb5dAfL9vHYAjPsrtyP1/wQHfgIyTTmO3Tet3OInoLmnBkBnmpuEzKsimC/anX
Hc4JnbaBFQ9V56i3jV443nahu0kgXSOoUuv1c0z4oFw=
-----END CERTIFICATE-----"""


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

    def test_create_self_signed_basic(self):
        """Create a self-signed certificate"""
        # Test with rsa:512 for speed purposes, the minimum key length
        res = core.create_self_signed(
            dn=dict(cn='Acme Industries'),
            newkey='rsa:512')
        self.assertTrue(res.get('success'), res.get('message'))
        self.assertTrue(res.get('cert', '').startswith(
            '-----BEGIN CERTIFICATE-----'))
        self.assertTrue(res.get('key', '').startswith(
            '-----BEGIN PRIVATE KEY-----'))

    def test_create_self_signed(self):
        """Create a self-signed certificate"""
        # Test with rsa:512 for speed purposes, the minimum key length
        now = get_utcnow_round()
        CN = "example.com"
        O = "Acme Corp"
        DAYS = 42
        res = core.create_self_signed(
            dn=dict(cn=CN, o=O),
            newkey='rsa:512',
            days=DAYS,
        )
        self.assertTrue(res.get('success'), res.get('message'))
        self.assertTrue(res.get('cert', '').startswith(
            '-----BEGIN CERTIFICATE-----'))

        res_parsed = parser.get_x509_as_json(
            text=res.get('cert'),
            openssl_path=self._openssl_path,
        )

        # Verify common name
        self.assertEqual(res_parsed['subject']['CN'], CN)
        self.assertEqual(res_parsed['issuer']['CN'], CN)
        # And organization
        self.assertEqual(res_parsed['subject']['O'], O)
        self.assertEqual(res_parsed['issuer']['O'], O)

        # Verify time delta
        not_before = du_parser.parse(res_parsed.get('notBefore'))
        not_after = du_parser.parse(res_parsed.get('notAfter'))
        self.assertGreaterEqual(not_before, now)
        delta = not_after - not_before
        self.assertEqual(delta.days, DAYS)

    def test_create_self_signed_san(self):
        """Create a self-signed certificate"""
        # Test with rsa:512 for speed purposes, the minimum key length
        CN = "Acme Corp"
        res = core.create_self_signed(
            dn=dict(cn=CN),
            newkey='rsa:512',
            alt_names=[
                'example.com',
                'www.example.com',
                '192.168.56.100',
                'hello@example.com',
                'http://www.example.com',
            ]
        )
        self.assertTrue(res.get('success'), "Message: {}\nConf: {}\n".format(
            res.get('message'), res.get("conf")
        ))
        self.assertTrue(res.get('cert', '').startswith(
            '-----BEGIN CERTIFICATE-----'))

        res_parsed = parser.get_x509_as_json(
            text=res.get('cert'),
            openssl_path=self._openssl_path,
        )

        # Verify common name
        self.assertEqual(res_parsed['subject']['CN'], CN)
        self.assertEqual(res_parsed['issuer']['CN'], CN)

        # Verify Subject Alternative Name

        san = get_san_from_extensions(res_parsed['extensions'])
        self.assertEqual(len(san), 5)
        self.assertEqual(sorted(san), sorted([
            "DNS:example.com",
            "DNS:www.example.com",
            "IP Address:192.168.56.100",
            "email:hello@example.com",
            "URI:http://www.example.com"
        ]))

    def test_load_req(self):
        with tempfile.NamedTemporaryFile(suffix='.csr', mode='w+') as f:
            f.write(CSR_SAN)
            f.flush()
            san = parser.extract_san_from_req(
                path=f.name,
                openssl_path=self._openssl_path,
            )
            self.assertEqual(
                sorted(san),
                [
                    "192.168.56.100",
                    "acme.org",
                    "cdn1.far-away.com",
                    "www.acme.org",
                ]
            )

    def test_load_x509(self):
        res = parser.get_x509_as_json(
            text=SIGNED_SAN, openssl_path=self._openssl_path)
        print(json.dumps(res, indent=4))




if __name__ == "__main__":
    unittest.main()
