#!/usr/bin/env python3
import glob
import os
import tempfile

from . import info
from .core import extract_san_from_req, make_san_section
from .distinguished_name import (
    DistinguishedName,
    make_dn_section,
)
from .helpers import execute_cmd


class CA(object):
    """Certificate Authority, using an openssl CA folder structure
    as a flat-file database.

    :param ca_path: path where to create the required folder structure
    """
    def __init__(self, ca_path=None):
        if not ca_path:
            raise ValueError("Missing ca_path")
        self._ca_path = ca_path

    DB_VERSION = 1
    _DB_VERSION_FILENAME = "db_version.txt"

    # https://www.phildev.net/ssl/creating_ca.html
    # http://pki-tutorial.readthedocs.io/en/latest/index.html

    _CA_CONF = """
[ req ]
prompt = no
distinguished_name = req_distinguished_name
req_extension      = v3_req

[ req_distinguished_name ]
{dn}

[ ca ]
default_ca = CA_dev

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

    _CA_CONF_SIGN_EXT = """
[ usr_cert_sign ]
basicConstraints = CA:false
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
{csr_san}
    """

    def initialize(
        self,
        dn=None,
        alt_names=None,
        days=90,
        newkey='rsa:2048',
    ):
        """Initialize a Certificate Authority.
        This creates a folder structure containing a root CA, public and
        private keys, and folders for Certificate Signing Requests and
        SignedCertificates.

        :param dn: a :py:class:`DistinguishedName` or :py:class:`dict`
        :param alt_names: a list of of Subject Alternative Names
        :param days: how many days in the future the CA will be valid
        :param newkey: key specification like 'rsa:2048'
        :returns: a dict with the members *success* and *message* always set
        """
        ca_path = self._ca_path
        dn_str = make_dn_section(dn)
        print("dn_str is: {}".format(dn_str))
        self._make_ca_structure()

        key_path = os.path.join(ca_path, 'private', 'cakey.pem')
        cert_path = os.path.join(ca_path, 'cacert.pem')
        careq_path = os.path.join(ca_path, 'careq.pem')
        config_path = os.path.join(ca_path, 'openssl.conf')

        conf = self._CA_CONF.format(
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

    def _make_ca_structure(self):
        basepath = self._ca_path
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
        with open(os.path.join(basepath,
                  self._DB_VERSION_FILENAME), 'w+') as f:
            f.write(str(self.DB_VERSION))

    def _read_ca_version(self):
        with open(os.path.join(
                self._ca_path, self._DB_VERSION_FILENAME)) as f:
            return int(f.read())

    @property
    def initialized(self):
        """
        :returns boolean: true if initialized
        """
        pass

    def get_info(self):
        """Get information about the CA in ca_path.

        :param ca_path: Path to Certificate Authority
        :returns: JSON object with status
        """
        ca_path = self._ca_path
        try:
            try:
                with open(os.path.join(ca_path, 'cacert.pem')) as f:
                    buf = f.read()

                details = info.load_x509(buf)
            except Exception as e:
                details = {
                    "error": str(e)
                }
            return {
                "initialized": True,
                "version": self._read_ca_version(),
                "details": details
            }
        except Exception as e:
            return {
                "initialized": False,
                "error": str(e),
            }

    def list_requests(self):
        """Get a list of Certificate Signing Requests.

        :returns: list --
            a list of {"id": <id>, "last_modified": <datastring>}
        """
        folder_path = os.path.join(self._ca_path, "certreqs")
        suffix = ".csr"
        paths = glob.glob(os.path.join(folder_path, '*' + suffix))
        ret = []
        for path in paths:
            basename = os.path.basename(path)
            if basename.endswith(suffix):
                last_modified = os.path.getmtime(path)
                item_id = basename[:-len(suffix)]
                ret.append({
                    "id": item_id,
                    "last_modified": last_modified,
                })
        return ret

    def get_request(self, serial=None):
        """Get details of a certificate signing request

        :param serial: serial number of request
        :return: a dict with information
        """
        path = os.path.join(self._ca_path, 'certreqs', serial + '.csr')
        if not os.path.exists(path):
            raise ValueError(path)
            return None

        with open(path) as f:
            return info.load_csr(f.read())

    def list_certificates(self):
        """Get a list of signed certificates"""
        # http://pki-tutorial.readthedocs.io/en/latest/cadb.html
        index_path = os.path.join(self._ca_path, "index.txt")
        with open(index_path) as f:
            lines = f.readlines()

        ret = []
        errors = []
        for line in lines:
            try:
                status, expires, revoked, serial, filename, name =\
                    line.split('\t')
                ret.append(dict(
                    status=status,
                    expires=expires,
                    revoked=revoked,
                    id=serial,
                    filename=None if filename == 'unknown' else filename,
                    name=name,
                ))
            except Exception as e:
                errors.append(str(e))
        return ret

    def get_certificate(self, serial=None):
        """Get details of a signed certificate"""
        path = os.path.join(self._ca_path, "certsdb", serial + ".pem")
        if os.path.exists(path):
            with open(path) as f:
                parsed = info.load_x509(f.read())
            return {
                "success": True,
                "details": parsed,
            }
        else:
            return {
                "message": "File not found",
                "success": False,
            }

    def revoke_certificate(self, serial=None):
        # revoke certificate
        # - openssl ca -config ./openssl.conf -revoke certsdb/XXX.pem
        # create crls
        # - openssl ca -config ./openssl.conf -gencrl -out crl/cacert.crl
        pass

    def sign_request(self, csr=None, days=90):
        """Sign a Certificate Signing Request.
        This function carries over Subject Alternative Name entries from the
        request.

        :param csr: a string with the CSR in PEM format
        :param days: how many days in the future the certificate will be valid
        :returns: a dict with the members *success* and *message* always set
        """
        ca_path = self._ca_path
        try:
            fileno_csr, csr_path = tempfile.mkstemp(suffix='.csr')
            fileno_conf, ext_conf_path = tempfile.mkstemp(suffix='.conf')

            api_version = self._read_ca_version()
            print("API version of CA: {}".format(api_version))

            alt_names = extract_san_from_req(csr)

            conf_path = os.path.join(self._ca_path, 'openssl.conf')

            conf = (self._CA_CONF_SIGN_EXT).format(
                san="",
                ca_path=ca_path,
                dn="",
                csr_san=make_san_section(alt_names)
            )

            with open(ext_conf_path, 'w+') as f:
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
                '-extfile',
                ext_conf_path,
                '-days',
                str(days),
                '-extensions',
                'usr_cert_sign',
                '-infiles',
                csr_path,
            ]

            success, message = execute_cmd(cmd)
            if success:
                details = info.load_x509(message)
                if details.get('serial'):
                    serial = details.get('serial')
                    csr_db_path = os.path.join(
                        ca_path, 'certreqs', '{:X}.csr'.format(serial)
                    )
                    with(open(csr_db_path, 'w+')) as f:
                        f.write(csr)
                    hex_serial = "{:X}".format(serial)
                else:
                    hex_serial = None
                return {
                    "success": True,
                    "message": "OK",
                    "cert": message,
                    "serial": hex_serial,
                }
            else:
                print("cmd: {}".format(cmd))
                print("conf\n----\n{}".format(conf))
                return {
                    "success": False,
                    "message": message
                }
        finally:
            os.unlink(csr_path)
            os.unlink(ext_conf_path)

__all__ = [
    'CA',
    'DistinguishedName',
]
