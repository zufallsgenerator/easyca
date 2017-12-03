#!/usr/bin/env python3
import datetime
import shutil
import tempfile
import unittest

from context import (
    CA,
    info,
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


def get_utcnow_round():
    return datetime.datetime.utcnow().replace(
        tzinfo=du_tz.tzutc(),
        microsecond=0,
    )


def get_san_from_extensions(extensions):
    for ext in extensions:
        if ext['name'] == 'subjectAltName':
            return [
                e.strip() for e in ext['str'].split(",")
            ]
    return


class Test(unittest.TestCase):
    def setUp(self):
        self._tempdirs = []

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

    def test_create_ca(self):
        ca_path = self.create_tempdir()
        common_name = "Acme Root CA"
        ca = CA(ca_path=ca_path)
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

        res_parsed = info.load_x509(res.get('cert'))

        san = get_san_from_extensions(res_parsed['extensions'])

        self.assertEqual(len(san), 5)
        self.assertEqual(sorted(san), sorted([
            "DNS:acme.com",
            "DNS:www.acme.com",
            "IP Address:192.168.56.100",
            "email:hello@example.com",
            "URI:http://www.example.com"
        ]))

    def test_create_ca_and_sign_cert(self):
        """Create a CA and sign certificates with it"""
        ca_path = self.create_tempdir()
        common_name = "Acme Root CA"
        ca = CA(ca_path=ca_path)
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

        res_parsed = info.load_x509(res_cert.get('cert'))
        self.assertEqual(res_parsed['issuer']['CN'], common_name)
        self.assertEqual(res_parsed['subject']['CN'], 'example.com')

        # SAN certificate
        res_cert_san = ca.sign_request(CSR_SAN)
        self.assertTrue(res_cert_san.get('success'), "Message: {}\n".format(
            res_cert_san.get('message')))

        res_parsed = info.load_x509(res_cert_san.get('cert'))

        self.assertEqual(res_parsed['issuer']['CN'], common_name)
        self.assertEqual(res_parsed['subject']['O'], 'Acme Machines INC')

        requests = ca.list_requests()
        self.assertEqual(len(requests), 2)

        certs = ca.list_certificates()
        self.assertTrue(len(certs) > 0)

        for cert in certs:
            cert_res = ca.get_certificate(serial=cert['id'])
            self.assertTrue(cert_res is not None)


if __name__ == "__main__":
    unittest.main()