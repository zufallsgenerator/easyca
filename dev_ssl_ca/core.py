#!/usr/bin/env python3

import subprocess
import tempfile
import shutil
import os
import re


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
basicConstraints=critical,CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
{extensions_line}

[ req_distinguished_name ]
{dn}

{extensions_section}
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

EXT_SEC_TPL = """[ v3_ca ]
subjectAltName = @alt_names

[ alt_names ]
{alt_names}"""

EXT_LINE = "x509_extensions = v3_ca"


def is_ip(name):
    if re.match(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$", name):
        return True
    return False


def is_ipv6(name):
    if re.match(r"^[0-9a-fA-F:\.]+$", name):
        return True
    return False


def is_uri(name):
    if re.match(r"^[a-z0-9]+:\/\/", name):
        return True
    return False


def is_email(name):
    return "@" in name and not is_uri(name)


def format_alt_names(alt_names):
    dns_idx = 1
    ip_idx = 1
    email_idx = 1
    uri_idx = 1

    ret = []
    for name in alt_names:
        if is_ip(name) or is_ipv6(name):
            ret.append("IP.{} = {}".format(ip_idx, name))
            ip_idx += 1
        elif is_email(name):
            ret.append("email.{} = {}".format(email_idx, name))
            email_idx += 1
        elif is_uri(name):
            ret.append("URI.{} = {}".format(uri_idx, name))
            uri_idx += 1
        else:
            ret.append("DNS.{} = {}".format(dns_idx, name))
            dns_idx += 1

    return "\n".join(ret)


def make_san_line_and_section(alt_names):
    if not alt_names:
        return '', ''

    extensions_section = EXT_SEC_TPL.format(
        alt_names=format_alt_names(alt_names))
    extensions_line = EXT_LINE

    return extensions_line, extensions_section


def create_self_signed(dn=None, alt_names=None, days=90, newkey='rsa:4096'):

    dn_str = ""
    for conf_key, arg_key in DEFAULT_CONF_ARGS.items():
        if dn.get(arg_key):
            dn_str += "{} = {}\n".format(conf_key, dn.get(arg_key))

    extensions_line, extensions_section = make_san_line_and_section(alt_names)

    tpl = CONF_TPL.format(
        dn=dn_str,
        extensions_line=extensions_line,
        extensions_section=extensions_section,
    )

    try:
        tmp_path = tempfile.mkdtemp()
        key_path = os.path.join(tmp_path, 'key.pem')
        cert_path = os.path.join(tmp_path, 'cert.pem')
        config_path = os.path.join(tmp_path, 'openssl.conf')

        with open(config_path, 'w+') as f:
            f.write(tpl)

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
                "message": message
            }
        else:
            return {
                "success": False,
                "message": message,
            }
    finally:
        shutil.rmtree(tmp_path)