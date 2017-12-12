#!/usr/bin/env python3
import glob
import logging
import os
import re
import tempfile

import arrow

from . import parser
from .core import make_san_section
from .distinguished_name import (
    DistinguishedName,
    make_dn_section,
)
from .exceptions import get_exception_from_openssl_output
from .helpers import execute_cmd


logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


ISODATE_TPL = '%Y-%m-%dT%H:%M:%SZ'


def parse_cert_index_date(date_str):
    if len(date_str) == 13 and date_str[12] == 'Z':
        dt = arrow.get(date_str, 'YYMMDDHHmmssz')
        return dt.strftime(ISODATE_TPL)
    else:
        return date_str


def parse_revoked_str(revoked_str):
    if "," in revoked_str:
        date_str, reason = revoked_str.split(",")[:2]
        return parse_cert_index_date(date_str), reason
    else:
        return parse_cert_index_date(revoked_str), None


def epoch_to_date(epoch):
    return arrow.get(epoch).strftime(ISODATE_TPL)


class CAPaths(object):
    def __init__(self, basepath):
        self._basepath = basepath
        self.certs = os.path.join(basepath, 'certs')
        self.reqs = os.path.join(basepath, 'reqs')
        self.private = os.path.join(basepath, 'private')
        self.config = os.path.join(basepath, 'openssl.conf')
        self.key = os.path.join(self.private, 'cakey.pem')
        self.root_ca = os.path.join(basepath, 'cacert.pem')
        self.root_csr = os.path.join(basepath, 'careq.pem')
        self.crl = os.path.join(basepath, 'crl')


class CA(object):
    """Certificate Authority, using an openssl CA folder structure
    as a flat-file database.

    :param ca_path: path where to create the required folder structure
    :param openssl_path: path of openssl binary to use
    """
    def __init__(self, ca_path=None, openssl_path=None):
        if not ca_path:
            raise ValueError("Missing ca_path")
        self._ca_path = ca_path
        if openssl_path:
            self._openssl_path = openssl_path
        else:
            self._openssl_path = self._get_openssl_path()

        self.openssl_version = self._get_openssl_version(self._openssl_path)
        log.debug("openssl_path: {}, openssl_version: {}".format(
            self._openssl_path, self.openssl_version))

    @property
    def ca_path(self):
        return self._ca_path

    def _get_openssl_path(self):
        """Get openssl binary in path

        :return string: openssl path
        """
        with os.popen('which openssl') as f:
            return f.read().strip()

    def _get_openssl_version(self, openssl_path):
        success, message = execute_cmd([openssl_path, 'version'])
        if success:
            m = re.search('OpenSSL ([0-9]+)\.([0-9]+)\.([0-9]+)', message)
            if m:
                return tuple([int(n) for n in m.groups()])
            else:
                log.error("Failed extracting openssl version from "
                          "string: '{}'".format(message))
        log.error("Failed getting openssl version: {}".format(message))
        return None

    DB_VERSION = 1
    _DB_VERSION_FILENAME = "db_version.txt"

    # https://www.phildev.net/ssl/creating_ca.html
    # http://pki-tutorial.readthedocs.io/en/latest/index.html

    _CA_CONF = """
[ req ]
utf8 = yes
prompt = no
distinguished_name = req_distinguished_name
req_extension      = v3_req

[ req_distinguished_name ]
{dn}

[ ca ]
default_ca = CA_dev

[ CA_dev ]
dir             = {ca_path}
certs       = $dir/certs
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
# crlDistributionPoints = URI:http://example.com/root.crl
{san}
"""

    _CA_CONF_SIGN_EXT = """
[ usr_cert_sign ]
basicConstraints = CA:false
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
{csr_san}
    """

    _INIT_CA_INSTRUCTIONS = """This folder of this CA doesn't seem to be
initialized. Call initialize() with at least
the arguments dn={"cn": "(some name here)"} set.
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
        :raise ValueError: missing value needed
        :raise FileExistsErrror: a CA is alreay initialized at this location
        :raise OpenSSLError: an error occurred calling openssl
        :returns: a dict with the members *success* and *message* always set
        """
        ca_path = self._ca_path

        if dn is None:
            raise ValueError("missing argument dn")

        dn_str = make_dn_section(dn)
        log.debug("dn_str is: {}".format(dn_str))
        self._make_ca_structure()

        paths = self.paths

        conf = self._CA_CONF.format(
            san=make_san_section(alt_names),
            ca_path=ca_path,
            dn=dn_str,
        )

        with open(paths.config, 'wb+') as f:
            f.write(conf.encode('utf-8'))

        cmd = [
            self._openssl_path,
            'req',
            '-nodes',
            '-new',
            '-utf8',
            '-newkey',
            newkey,
            '-keyout',
            paths.key,
            '-out',
            paths.root_csr,
            '-config',
            paths.config,
        ]
        success, message = execute_cmd(cmd)
        if not success:
            raise get_exception_from_openssl_output(message)

        cmd = [
            self._openssl_path,
            'ca',
            '-config',
            paths.config,
            '-utf8',
            '-batch',
            '-name',
            'CA_dev',
            '-create_serial',
            '-out',
            paths.root_ca,
            '-days',
            str(days),
            '-keyfile',
            paths.key,
            '-selfsign',
            '-extensions',
            'v3_ca_has_san',
            '-infiles',
            paths.root_csr,
        ]
        log.debug("Creating CA...")
        log.debug("{}".format(" ".join(cmd)))
        success, message = execute_cmd(cmd)
        if not success:
            raise get_exception_from_openssl_output(message)

        with open(paths.key) as key_file:
            key = key_file.read()
        with open(paths.root_ca) as cert_file:
            cert = cert_file.read()
        return {
            "success": success,
            "message": message,
            "cert": cert,
            "key": key,
            "conf": conf,
        }

    @property
    def paths(self):
        if not getattr(self, '_path_holder', None):
            self._path_holder = CAPaths(self._ca_path)
        return self._path_holder

    def _make_ca_structure(self):
        log.info("Createing CA file structure at: '{}'".format(self._ca_path))
        basepath = self._ca_path
        version_path = os.path.join(
            basepath,
            self._DB_VERSION_FILENAME
        )
        if os.path.exists(version_path):
            raise FileExistsError(version_path)
        paths = self.paths
        folder_perms = [
            (paths.certs, 0o750),
            (paths.reqs, 0o750),
            (paths.crl, 0o750),
            (paths.private, 0o700),
        ]
        for path, perm in folder_perms:
            os.makedirs(path)
            os.chmod(path, perm)
        with open(os.path.join(basepath, 'index.txt'), 'w+') as f:
            f.write('')
        with open(os.path.join(basepath, 'rootcas.txt'), 'w+') as f:
            f.write('')
        with open(version_path, 'wb+') as f:
            f.write(str(self.DB_VERSION).encode('utf-8'))

    def _read_ca_version(self):
        with open(os.path.join(
                self._ca_path, self._DB_VERSION_FILENAME)) as f:
            return int(f.read())

    def _get_db_settings(self):
        with open(os.path.join(
                self._ca_path, 'index.txt.attr')) as f:
            text = f.read()

        ret = {}
        for line in [l.strip() for l in text.splitlines()]:
            if "=" in line:
                idx = line.index('=')
                key = line[:idx].strip()
                value = line[idx + 1:].strip()
                ret[key] = value
        return ret

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
        try:
            with open(self.paths.root_ca) as f:
                buf = f.read()

            rootca = parser.get_x509_as_json(
                text=buf,
                openssl_path=self._openssl_path,
            )
            db_settings = self._get_db_settings()
            return {
                "initialized": True,
                "easyca_api_version": self._read_ca_version(),
                "rootca": rootca,
                "db_settings": db_settings,
            }
        except UnicodeDecodeError:
            raise
        except Exception as e:
            return {
                "initialized": False,
                "error": str(e),
                "instructions": self._INIT_CA_INSTRUCTIONS
            }

    def updatedb(self):
        """Updates the database index to purge expired certificates.
        """
        config_path = os.path.join(self._ca_path, 'openssl.conf')
        cmd = [
            self._openssl_path,
            'ca',
            '-config',
            config_path,
            '-updatedb'
        ]
        success, message = execute_cmd(cmd)
        return {
            "success": success,
            "message": message
        }

    def list_requests(self):
        """Get a list of Certificate Signing Requests.

        :returns: list --
            a list of {"id": <id>, "last_modified": <datastring>}
        """
        folder_path = self.paths.reqs
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
                    "last_modified": epoch_to_date(last_modified),
                })
        return ret

    def get_request(self, serial=None):
        """Get details of a certificate signing request

        :param serial: serial number of request
        :raise LookupError: request with serial not found
        :return: a dict with information
        """
        path = os.path.join(self.paths.reqs, serial + '.csr')
        if not os.path.exists(path):
            raise LookupError(path)

        return parser.get_request_as_json(
            path=path, openssl_path=self._openssl_path)

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
                    [c.strip() for c in line.split('\t')]
                revoked_date, revoked_reason = parse_revoked_str(revoked)
                ret.append(dict(
                    status=status,
                    expires=parse_cert_index_date(expires),
                    revoked=revoked_date,
                    revoked_reason=revoked_reason,
                    id=serial,
                    filename=None if filename == 'unknown' else filename,
                    name=parser.transform_distinguished_name(name),
                ))
            except Exception as e:
                logging.error("CA.list_certificates -> {}".format(e))
                errors.append(str(e))
        return ret

    def get_certificate(self, serial=None):
        """Get details of a signed certificate

        :param serial: serial number of request
        :raise LookupError: certificate with serial not found
        :return: a dict with information
        """
        path = self._get_cert_path(serial=serial)
        if os.path.exists(path):
            parsed = parser.get_x509_as_json(
                path=path, openssl_path=self._openssl_path)
            return {
                "success": True,
                "details": parsed,
            }
        else:
            raise LookupError("Certificate with serial '{}' not found".format(
                serial))

    def revoke_certificate(self, serial=None):
        cert_path = self._get_cert_path(serial=serial)
        if not os.path.exists(cert_path):
            raise LookupError("Certificate with serial '{}' not found".format(
                serial))

        config_path = os.path.join(self._ca_path, 'openssl.conf')
        cmd = [
            self._openssl_path,
            'ca',
            '-config',
            config_path,
            '-revoke',
            cert_path
        ]
        success, message = execute_cmd(cmd)
        if success:

            # revoke certificate
            # - openssl ca -config ./openssl.conf -revoke certsdb/XXX.pem
            # create crls
            # - openssl ca -config ./openssl.conf -gencrl -out crl/cacert.crl
            return {
                "success": success,
                "message": message
            }
        else:
            raise get_exception_from_openssl_output(message)

    def _get_cert_path(self, serial=None):
        return os.path.join(self.paths.certs, serial + ".pem")

    def get_request_name_from_path(self, path):
        return parser.get_request_name(
            path=path, openssl_path=self._openssl_path)

    def sign_request(self, csr=None, days=90):
        """Sign a Certificate Signing Request.
        This function carries over Subject Alternative Name entries from the
        request.

        :param csr: a string with the CSR in PEM format
        :param days: how many days in the future the certificate will be valid
        :raise ValueError: when the input is not a certificate request
        :return: a dict with the members *success* and *message* always set
        """
        ca_path = self._ca_path
        if csr is None:
            raise ValueError("csr cannot be None")
        try:
            _, ext_conf_path = tempfile.mkstemp(suffix='.conf')
            _, csr_path = tempfile.mkstemp(suffix='.csr')

            api_version = self._read_ca_version()
            log.debug("sign_request -> API version of CA: {}".format(
                api_version))

            alt_names = parser.extract_san_from_req(
                text=csr,
                openssl_path=self._openssl_path,
            )
            log.debug("sign_request -> alt_names: {}".format(alt_names))
            log.info("Signing request. days: {}, altNames: {}".format(
                90, alt_names))

            conf_path = os.path.join(self._ca_path, 'openssl.conf')

            conf = (self._CA_CONF_SIGN_EXT).format(
                san="",
                ca_path=ca_path,
                dn="",
                csr_san=make_san_section(alt_names)
            )

            with open(ext_conf_path, 'wb+') as f:
                f.write(conf.encode('utf-8'))

            with open(csr_path, 'wb+') as f:
                f.write(csr.encode('utf-8'))

            cmd = [
                self._openssl_path,
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

            success, message = execute_cmd(cmd, text=csr)
            if success:
                details = parser.get_x509_as_json(
                    text=message,
                    openssl_path=self._openssl_path
                )
                if details.get('serial'):
                    serial = details.get('serial')
                    csr_db_path = os.path.join(
                        self.paths.reqs, '{:X}.csr'.format(serial)
                    )
                    with(open(csr_db_path, 'wb+')) as f:
                        f.write(csr.encode('utf-8'))
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
                log.warning("Signing failed: cmd: {}".format(cmd))
                log.warning("Error:\n{}".format(message))
                log.debug("conf\n----\n{}".format(conf))
                e = get_exception_from_openssl_output(message)
                if e:
                    raise e
                raise Exception("Unknown error when signing request")
        finally:
            os.unlink(csr_path)
            os.unlink(ext_conf_path)

__all__ = [
    'CA',
    'DistinguishedName',
]
