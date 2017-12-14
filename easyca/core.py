#!/usr/bin/env python3
"""
Main module for creating Certificate Authorities and signing CSRs
"""
import glob
import os
import shutil
import tempfile


from . import distinguished_name
from . import san
from .helpers import execute_cmd


# references:
# https://www.phildev.net/ssl/opensslconf.html
# https://jamielinux.com/docs/openssl-certificate-authority/appendix/root-configuration-file.html


CONF_TPL_SELF_SIGNED = """[ req ]
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

CONF_TPL_NORMAL = """[ req ]
distinguished_name = req_distinguished_name
prompt             = no
req_extensions = req_ext

[ req_distinguished_name ]
{dn}

[ req_ext ]
{extensions_section}

"""


EXT_SEC_TPL = """subjectAltName = @alt_names

[ alt_names ]
{alt_names}"""


EXT_LINE = "x509_extensions = v3_ca"


def make_san_section(alt_names):
    if not alt_names:
        return ''

    formatted_alt_names = san.format_alt_names(alt_names)
    extensions_section = EXT_SEC_TPL.format(
        alt_names=formatted_alt_names)

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

    conf = CONF_TPL_SELF_SIGNED.format(
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


def make_filename(raw_name):
    return raw_name.replace(" ", "_").lower()


def create_request(
        dn=None,
        alt_names=None,
        newkey='rsa:2048',
        inkey=None,
        output_folder=None):
    """Create a Certificate Signing Request (CSR)

    :param dn: a dictionary with configuration for distinguished name
    :param alt_names: a list of of Subject Alternative Names
    :param days: how many days in the future the CA will be valid
    :param newkey: key specification like 'rsa:2048'
    :param inkey: path of key to use (newkey will be ignored)
    :returns: a dict with the members *success* and *message* always set
    """
    dn_str = distinguished_name.make_dn_section(dn)

    extensions_section = make_san_section(alt_names)

    conf = CONF_TPL_NORMAL.format(
        dn=dn_str,
        extensions_section=extensions_section,
    )
    assert(output_folder)

    with tempfile.NamedTemporaryFile(suffix='.conf', mode='wb+') as f:
        f.write(conf.encode('utf-8'))
        f.flush()
        config_path = f.name

        prefix = make_filename(dn['cn'])
        if not os.path.exists(output_folder):
            os.makedirs(output_folder)

        key_path = os.path.join(output_folder, '{}.key'.format(prefix))
        csr_path = os.path.join(output_folder, '{}.csr'.format(prefix))

        with open(key_path, 'w') as f:
            # Do flag
            f.write('')
        os.chmod(key_path, 0o600)

        if inkey:
            cmd = [
                'openssl',
                'req',
                '-new',
                '-sha256',
                '-key',
                inkey,
                '-nodes',
                '-out',
                csr_path,
                '-config',
                config_path,
            ]
        else:
            cmd = [
                'openssl',
                'req',
                '-sha256',
                '-newkey',
                newkey,
                '-nodes',
                '-keyout',
                key_path,
                '-out',
                csr_path,
                '-config',
                config_path,
            ]
        success, message = execute_cmd(cmd)
        if success:
            with open(key_path) as key_file:
                key = key_file.read()
            with open(csr_path) as csr_file:
                csr = csr_file.read()

            ret = {
                "csr": csr,
                "csr_path": csr_path,
                "message": message,
                "cmd": cmd,
                "conf": conf,
            }
            if not inkey:
                ret.update({
                    "key": key,
                    "key_path": key_path,
                })
            return ret

        else:
            raise ValueError(message)

__all__ = [
    'create_self_signed',
]
