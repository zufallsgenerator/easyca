#!/usr/bin/env python3

import subprocess
import tempfile
import shutil
import os


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

[ req_distinguished_name ]
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


def create_self_signed(**kvargs):

    tpl = CONF_TPL

    for conf_key, arg_key in DEFAULT_CONF_ARGS.items():
        if kvargs.get(arg_key):
            tpl += "{} = {}\n".format(conf_key, kvargs.get(arg_key))

        days = kvargs.get('days', 90)
        newkey = kvargs.get('newkey', 'rsa:4096')

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