#!/usr/bin/env python3

import subprocess
import tempfile
import shutil
import os
from . import san




# references:
# https://www.phildev.net/ssl/opensslconf.html
# https://jamielinux.com/docs/openssl-certificate-authority/appendix/root-configuration-file.html


def execute_cmd(cmd):
    proc = subprocess.run(
        cmd,
        shell=False,
        check=False,
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE
    )
    if proc.returncode == 0:
        return True, proc.stdout.decode()
    else:
        return False, proc.stderr.decode()


CONF_TPL = """[ req ]
distinguished_name = req_distinguished_name
prompt             = no
x509_extensions    = v3_ca
req_extension      = v3_req

[ req_distinguished_name ]
{dn}

[ v3_ca ]
{extensions_section}

[ v3_req ]
basicConstraints=critical,CA:True
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
"""

DEFAULT_CONF_ARGS = dict(
    C='c',
    ST='st',
    L='l',
    O='o',
    OU='ou',
    CN='cn',
    emailAddress='email',
)

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


def make_dn_section(dn):
    dn_str = ""
    for conf_key, arg_key in DEFAULT_CONF_ARGS.items():
        if dn and dn.get(arg_key):
            dn_str += "{} = {}\n".format(conf_key, dn.get(arg_key))
    return dn_str


def create_self_signed(dn=None, alt_names=None, days=90, newkey='rsa:2048'):
    dn_str = make_dn_section(dn)

    extensions_section = make_san_section(alt_names)

    conf = CONF_TPL.format(
        dn=dn_str,
        extensions_section=extensions_section,
    )
    return _gen_cert(conf=conf, days=days, newkey=newkey)


def _gen_cert(conf=None, days=None, newkey=None):
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


def sign_cert(csr=None, ca_path=None, days=90):
    conf_path = os.path.join(ca_path, 'openssl.conf')

    try:
        fileno, csr_path = tempfile.mkstemp(suffix='.csr')

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
            'usr_cert_has_san',
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




# https://www.phildev.net/ssl/creating_ca.html

CA_CONF = """
[ req ]
prompt = no
distinguished_name = req_distinguished_name
req_extension      = v3_req

[ req_distinguished_name ]
{dn}

[ v3_ca ]
{san}


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
countryName     = optional
stateOrProvinceName = optional
localityName        = optional
organizationName    = optional
organizationalUnitName  = optional
commonName      = supplied
emailAddress        = optional

# https://www.phildev.net/ssl/creating_ca.html
####################################################################
# Extensions for when we sign normal certs (specified as default)
[ usr_cert ]
basicConstraints = CA:false
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName = email:move

####################################################################
# Same as above, but cert req already has SubjectAltName
[ usr_cert_has_san ]
basicConstraints = CA:false
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer

####################################################################
# Extensions to use when signing a CA
[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints = CA:true
subjectAltName=email:move

####################################################################
# Same as above, but CA req already has SubjectAltName
[ v3_ca_has_san ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints = CA:true
"""


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


def create_ca(
    ca_path=None,
    dn=None,
    alt_names=None,
    days=90,
    newkey='rsa:2048',
):
    dn_str = make_dn_section(dn)
    extensions_section = make_san_section(alt_names)

    make_ca_structure(ca_path)

    key_path = os.path.join(ca_path, 'private', 'cakey.pem')
    cert_path = os.path.join(ca_path, 'cacert.pem')
    careq_path = os.path.join(ca_path, 'careq.pem')
    config_path = os.path.join(ca_path, 'openssl.conf')

    conf = CA_CONF.format(san=make_san_section([
        'example.com',
        'webmaster@example.com',
    ]),
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
    print(message)

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
        'usr_cert_has_san',
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
