#!/usr/bin/env python3
import glob
import os
import tempfile

from . import core
from . import distinguished_name
from . import info
from . import san
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

        :param dn: a dictionary with configuration for distinguished name
        :param alt_names: a list of of Subject Alternative Names
        :param days: how many days in the future the CA will be valid
        :param newkey: key specification like 'rsa:2048'
        :returns: a dict with the members *success* and *message* always set
        """
        ca_path = self._ca_path
        dn_str = distinguished_name.make_name_section(dn)
        core.make_ca_structure(ca_path)

        key_path = os.path.join(ca_path, 'private', 'cakey.pem')
        cert_path = os.path.join(ca_path, 'cacert.pem')
        careq_path = os.path.join(ca_path, 'careq.pem')
        config_path = os.path.join(ca_path, 'openssl.conf')

        conf = core.CA_CONF.format(
            san=core.make_san_section(alt_names),
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
                "version": core.read_ca_version(ca_path),
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

    def get_request(self, name=None):
        """Get details of a certificate signing request"""
        pass

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
            fileno_conf, conf_path = tempfile.mkstemp(suffix='.conf')

            api_version = core.read_ca_version(ca_path)
            print("API version of CA: {}".format(api_version))

            alt_names = core.extract_san_from_req(csr)

            conf = (core.CA_CONF + core.CA_CONF_SIGN_EXT).format(
                san="",
                ca_path=ca_path,
                dn="",
                csr_san=core.make_san_section(alt_names)
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
            os.unlink(conf_path)
