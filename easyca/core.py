#!/usr/bin/env python3
"""
Main module for creating Certificate Authorities and signing CSRs
"""
import glob
import os
import shutil
import tempfile

import OpenSSL

from . import distinguished_name
from . import san
from .helpers import execute_cmd
from .info import load_x509


# references:
# https://www.phildev.net/ssl/opensslconf.html
# https://jamielinux.com/docs/openssl-certificate-authority/appendix/root-configuration-file.html


CONF_TPL = """[ req ]
distinguished_name = req_distinguished_name
prompt             = no
x509_extensions    = v3_ca

[ req_distinguished_name ]
{dn}

[ v3_ca ]
basicConstraints = CA:false
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
extendedKeyUsage = serverAuth,clientAuth
{extensions_section}

"""


EXT_SEC_TPL = """subjectAltName = @alt_names

[ alt_names ]
{alt_names}"""

EXT_LINE = "x509_extensions = v3_ca"


def make_san_section(alt_names):
    if not alt_names:
        return ''

    extensions_section = EXT_SEC_TPL.format(
        alt_names=san.format_alt_names(alt_names))

    return extensions_section


def create_self_signed(dn=None, alt_names=None, days=90, newkey='rsa:2048'):
    """Create a self-signed certificate.

    :param dn: a dictionary with configuration for distinguished name
    :param alt_names: a list of of Subject Alternative Names
    :param days: how many days in the future the CA will be valid
    :param newkey: key specification like 'rsa:2048'
    :returns: a dict with the members *success* and *message* always set
    """
    dn_str = distinguished_name.make_dn_section(dn)

    extensions_section = make_san_section(alt_names)

    conf = CONF_TPL.format(
        dn=dn_str,
        extensions_section=extensions_section,
    )

    try:
        tmp_path = tempfile.mkdtemp()
        key_path = os.path.join(tmp_path, 'key.pem')
        cert_path = os.path.join(tmp_path, 'cert.pem')
        config_path = os.path.join(tmp_path, 'openssl.conf')

        with open(config_path, 'w+') as f:
            f.write(conf)

        cmd = [
            'openssl',
            'req',
            '-newkey',
            newkey,
            '-nodes',
            '-keyout',
            key_path,
            '-x509',
            '-days',
            str(days),
            '-out',
            cert_path,
            '-config',
            config_path,
        ]
        success, message = execute_cmd(cmd)
        if success:
            with open(key_path) as key_file:
                key = key_file.read()
            with open(cert_path) as cert_file:
                cert = cert_file.read()

            return {
                "success": True,
                "cert": cert,
                "key": key,
                "message": message,
                "cmd": cmd,
                "conf": conf,
            }
        else:
            return {
                "success": False,
                "message": message,
                "cmd": cmd,
                "conf": conf,
            }
    finally:
        shutil.rmtree(tmp_path)


def extract_san_from_req(buf):
    """Get a list of SAN from a Certificate Signing Request"""
    req = OpenSSL.crypto.load_certificate_request(
        OpenSSL.crypto.FILETYPE_PEM, buf)

    san = []
    for ext in req.get_extensions():
        short_name = ext.get_short_name().decode()
        if short_name == "subjectAltName":
            parts = [p.strip() for p in ext.__str__().split(',')]
            for p in parts:
                if ":" in p:
                    idx = p.index(":")
                    san.append(p[idx + 1:])

    return san




__all__ = [
    'create_self_signed',
]
