#!/usr/bin/env python3
"""
Main module for creating Certificate Authorities and signing CSRs
"""
import subprocess
import tempfile
import shutil
import os
import OpenSSL
from . import san
from . import distinguished_name

# references:
# https://www.phildev.net/ssl/opensslconf.html
# https://jamielinux.com/docs/openssl-certificate-authority/appendix/root-configuration-file.html


def execute_cmd(cmd):
    # subprocess.run came in version 3.5
    proc = subprocess.Popen(
        cmd,
        shell=False,
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE
    )
    stdout, stderr = proc.communicate()

    if proc.returncode == 0:
        return True, stdout.decode()
    else:
        return False, stderr.decode()


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
    dn_str = distinguished_name.make_name_section(dn)

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


def sign_cert(csr=None, ca_path=None, days=90):
    """Sign a Certificate Signing Request.
    This function carries over Subject Alternative Name entries from the
    request.

    :param csr: a string with the CSR in PEM format
    :param ca_path: path to folder structure created with :py:func:`create_ca`
    :param days: how many days in the future the certificate will be valid
    :returns: a dict with the members *success* and *message* always set
    """
    try:
        fileno_csr, csr_path = tempfile.mkstemp(suffix='.csr')
        fileno_conf, conf_path = tempfile.mkstemp(suffix='.conf')

        api_version = read_ca_version(ca_path)
        print("API version of CA: {}".format(api_version))

        alt_names = extract_san_from_req(csr)

        conf = (CA_CONF + CA_CONF_SIGN_EXT).format(
            san="",
            ca_path=ca_path,
            dn="",
            csr_san=make_san_section(alt_names)
        )

        with open(conf_path, 'w+') as f:
            f.write(conf)

        with open(csr_path, 'w+') as f:
            f.write(csr)

        cmd = [
            'openssl',
            'ca',
            '-batch',
            '-name',
            'CA_dev',
            '-config',
            conf_path,
            '-days',
            str(days),
            '-extensions',
            'usr_cert_sign',
            '-infiles',
            csr_path,
        ]

        success, message = execute_cmd(cmd)
        if success:
            return {
                "success": True,
                "message": "OK",
                "cert": message
            }
        else:
            return {
                "success": False,
                "message": message
            }
    finally:
        os.unlink(csr_path)
        os.unlink(conf_path)


# https://www.phildev.net/ssl/creating_ca.html

CA_CONF = """
[ req ]
prompt = no
distinguished_name = req_distinguished_name
req_extension      = v3_req

[ req_distinguished_name ]
{dn}


[ CA_dev ]
dir             = {ca_path}
certs       = $dir/certsdb
new_certs_dir   = $certs
database    = $dir/index.txt
certificate = $dir/cacert.pem
private_key = $dir/private/cakey.pem
serial      = $dir/serial
crldir      = $dir/crl
crlnumber   = $dir/crlnumber
crl     = $crldir/crl.pem
default_md = sha256
policy = policy_anything

[ policy_anything ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ v3_ca_has_san ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints = CA:true
{san}
"""


CA_CONF_SIGN_EXT = """
[ usr_cert_sign ]
basicConstraints = CA:false
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
{csr_san}
"""

AP_VERSION_FILENAME = "api_version.txt"
API_VERSION = 1


def make_ca_structure(basepath):
    folder_perms = [
        ('certsdb', 0o750),
        ('certreqs', 0o750),
        ('crl', 0o750),
        ('private', 0o700),
    ]
    for name, perm in folder_perms:
        path = os.path.join(basepath, name)
        os.makedirs(path)
        os.chmod(path, perm)
    with open(os.path.join(basepath, 'index.txt'), 'w+') as f:
        f.write('')
    with open(os.path.join(basepath, AP_VERSION_FILENAME), 'w+') as f:
        f.write(str(API_VERSION))


def read_ca_version(basepath):
    with open(os.path.join(basepath, AP_VERSION_FILENAME)) as f:
        return int(f.read())


def create_ca(
    ca_path=None,
    dn=None,
    alt_names=None,
    days=90,
    newkey='rsa:2048',
):
    """Create a Certificate Authority.
    This creates a folder structure containing a root CA, public and private
    keys, and folders for Certificate Signing Requests and Signed Certificates.

    :param ca_path: path where to create the required folder structure
    :param dn: a dictionary with configuration for distinguished name
    :param alt_names: a list of of Subject Alternative Names
    :param days: how many days in the future the CA will be valid
    :param newkey: key specification like 'rsa:2048'
    :returns: a dict with the members *success* and *message* always set
    """
    dn_str = distinguished_name.make_name_section(dn)
    make_ca_structure(ca_path)

    key_path = os.path.join(ca_path, 'private', 'cakey.pem')
    cert_path = os.path.join(ca_path, 'cacert.pem')
    careq_path = os.path.join(ca_path, 'careq.pem')
    config_path = os.path.join(ca_path, 'openssl.conf')

    conf = CA_CONF.format(
        san=make_san_section(alt_names),
        ca_path=ca_path,
        dn=dn_str,
    )

    with open(config_path, 'w+') as f:
        f.write(conf)

    cmd = [
        'openssl',
        'req',
        '-nodes',
        '-new',
        '-newkey',
        newkey,
        '-keyout',
        key_path,
        '-out',
        careq_path,
        '-config',
        config_path
    ]
    success, message = execute_cmd(cmd)
    if not success:
        raise ValueError(message)
        return {
            "success": success,
            "message": message,
            "conf": conf
        }

    cmd = [
        'openssl',
        'ca',
        '-config',
        config_path,
        '-utf8',
        '-batch',
        '-name',
        'CA_dev',
        '-create_serial',
        '-out',
        cert_path,
        '-days',
        str(days),
        '-keyfile',
        key_path,
        '-selfsign',
        '-extensions',
        'v3_ca_has_san',
        '-infiles',
        careq_path,
    ]
    print("Creating CA...")
    print("{}".format(" ".join(cmd)))
    success, message = execute_cmd(cmd)
    if not success:
        raise Exception(message)

    if success:
        with open(key_path) as key_file:
            key = key_file.read()
        with open(cert_path) as cert_file:
            cert = cert_file.read()
        return {
            "success": success,
            "message": message,
            "cert": cert,
            "key": key,
            "conf": conf,
        }

__all__ = [
    'create_ca',
    'sign_cert',
    'create_self_signed',
]
