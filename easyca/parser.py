#!/usr/bin/env python3
# Get info only using openssl, no libraries

import logging
import re

from dateutil import parser as dateparser
from dateutil.tz import tzutc as TZUTC

from .helpers import execute_cmd

EXT_PREFIX = "X509v3 "


logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


tzutc = TZUTC()


def parse_extensions_output(text):
    """Parse output from x509 and req commands dumping only the extensions"""
    lines = [l.strip() for l in text.split("\n") if l.strip()]

    if len(lines) < 2:
        return []

    if lines[0] in ('X509v3 extensions:', 'Requested Extensions:'):
        lines = lines[1:]

    extensions = []
    cur_header = None
    cur_data = []
    while lines:
        line = lines[0]
        lines = lines[1:]
        if line.startswith(EXT_PREFIX):
            log.debug("parse_extension_output -> in extension: {}".format(
                line))
            if cur_header:
                extensions.append({
                    "name": cur_header,
                    "str": "\n".join(cur_data)
                })
            cur_header = make_camel_case(line[len(EXT_PREFIX):].split(":")[0])
            cur_data = []
        else:
            cur_data.append(line)

    if cur_header and cur_data:
        extensions.append({
            "name": cur_header,
            "str": "\n".join(cur_data)
        })

    return extensions


def make_camel_case(text):
    ret = []
    parts = [p.lower().strip() for p in text.split(" ") if p.strip()]
    for i in range(0, len(parts)):
        p = parts[i]
        if i == 0:
            ret.append(p)
        else:
            ret.append(p[0].upper() + p[1:])

    return "".join(ret)


def get_x509_extensions(path=None, text=None, openssl_path=None):
    assert(openssl_path)
    cmd = [
        openssl_path,
        'x509',
        '-text',
        '-noout',
        '-certopt',
        # No linebreak between the two below here
        'no_aux,no_header,no_issuer,no_pubkey,no_serial,no_sigdump,'
        'no_signame,no_subject,no_subject,no_validity,no_version',
    ]

    if path:
        cmd += ['-in', path]
        success, message = execute_cmd(cmd)
    elif text is not None:
        success, message = execute_cmd(cmd, text=text)
    else:
        raise ValueError("Need path or text")

    if not success:
        raise Exception(message)
    return parse_extensions_output(message)


def get_request_as_json(path=None, text=None, openssl_path=None):
    success, message = _extract_req(
        path=path, text=text, openssl_path=openssl_path)
    if not success:
        raise Exception(message)

    details = parse_x509_output(message, transformers=FIELD_TRANSFORMERS)

    extensions = get_request_extensions_as_json(
        path=path, text=text, openssl_path=openssl_path)

    assert('extensions' not in details)
    details['extensions'] = extensions

    return details


def _extract_req(path=None, text=None, openssl_path=None):
    assert(openssl_path)
    if path and "-----" in path:
        raise ValueError("Should probably be text, not path")

    # TODO: missing: version, expired
    cmd = [
        openssl_path,
        'req',
        '-noout',
        '-subject',
    ]
    if path:
        cmd += ['-in', path]
        success, message = execute_cmd(cmd)
    else:
        success, message = execute_cmd(cmd, text)

    return success, message


def get_request_extensions_as_json(path=None, text=None, openssl_path=None):
    assert(openssl_path)
    # TODO: critical flag
    cmd = [
        openssl_path,
        'req',
        '-text',
        '-noout',
        '-reqopt',
        # No linebreak between the two below here
        'no_attributes,no_aux,no_header,no_issuer,no_pubkey,no_serial,'
        'no_sigdump,no_signame,no_subject,no_subject,no_validity,no_version',
    ]
    if path:
        cmd += ['-in', path]
        success, message = execute_cmd(cmd)
    elif text:
        success, message = execute_cmd(cmd, text=text)
    else:
        raise ValueError("Need either path or text")

    if not success:
        return {
            'success': False,
            'message': message
        }
    if success:
        return {
            'success': True,
            'extensions': parse_extensions_output(message)
        }


def extract_san_from_req(path=None, text=None, openssl_path=None):
    if openssl_path is None:
        raise ValueError("Need openssl_path to be set")
    san = []
    res = get_request_extensions_as_json(
        path=path, text=text, openssl_path=openssl_path
    )
    if not res.get("success"):
        return None
    for ext in res['extensions']:
        if ext['name'] == "subjectAlternativeName":
            parts = [p.strip() for p in ext['str'].split(',')]
            for p in parts:
                if ":" in p:
                    idx = p.index(":")
                    san.append(p[idx + 1:])

    return san


def transform_datestring(datestr):
    # Arrow has poor date parsing, so rely in dateutil for this
    return dateparser.parse(
        datestr).astimezone(tzutc).strftime('%Y-%m-%dT%H:%M:%SZ')


def transform_distinguished_name(name):
    # openssl 1.1.0 outputs subject=CN = example.com, O = Acme Corp
    # openssl 1.0.2 outputs subject= /O=Acme Corp/CN=example.com
    if re.match(r'\s*/', name):
        return _transform_distinguished_slash_prefix(name)
    if re.match(r'\s*[A-Z]+', name):
        return _transform_distinguished_comma_delim(name)

    raise ValueError("No recognized format: '{}'".format(name))


def _transform_distinguished_slash_prefix(name):
    # openssl 1.0.2 outputs subject= /O=Acme Corp/CN=example.com
    ret = {}
    rest = name
    while rest:
        m = re.search('\/([^\=]+)\=([^\/\=]+)', rest)
        if not m:
            return ret
        key, value = m.groups()
        ret[key] = decode_hex_utf8(value)
        rest = rest[m.span()[1]:]

    return ret


def _transform_distinguished_comma_delim(name):
    # openssl 1.1.0 outputs subject=CN = example.com, O = Acme Corp
    ret = {}

    parts = name.split(",")

    for part in parts:
        if "=" in part:
            idx = part.index("=")
        key, value = part[:idx].strip(), part[idx + 1:].strip()
        ret[key] = decode_hex_utf8(value)

    return ret


def transform_serial(hexstring):
    return int(hexstring, 16)


FIELD_TRANSFORMERS = {
    'notBefore': transform_datestring,
    'notAfter': transform_datestring,
    'subject': transform_distinguished_name,
    'issuer': transform_distinguished_name,
    'serial': transform_serial,
}


def transform_x509_field(key, raw_value, transformers=None):
    transformer = transformers.get(key)
    if transformer:
        return transformer(raw_value)

    return raw_value


def parse_x509_output(text, transformers=None):
    lines = [l.strip() for l in text.splitlines() if l.strip()]

    ret = {}
    for line in lines:
        try:
            idx = line.index('=')
        except ValueError:
            continue
        key = line[:idx]
        raw_value = line[idx + 1:].strip()

        if transformers:
            value = transform_x509_field(
                key, raw_value, transformers=transformers)
        else:
            value = raw_value

        ret[key] = value
    return ret


def get_x509_as_json(path=None, text=None, openssl_path=None):
    success, message = _extract_cert(
        path=path, text=text, openssl_path=openssl_path)
    if not success:
        raise Exception(message)

    details = parse_x509_output(message, transformers=FIELD_TRANSFORMERS)

    extensions = get_x509_extensions(
        path=path, text=text, openssl_path=openssl_path)

    assert('extensions' not in details)
    details['extensions'] = extensions

    return details


def get_request_name(path=None, text=None, openssl_path=None):

    success, message = _extract_req(
        path=path, text=text, openssl_path=openssl_path)
    if not success:
        raise Exception(message)
    details = parse_x509_output(message, transformers=None)
    return details.get('subject')


def _extract_cert(path=None, text=None, openssl_path=None):
    assert(openssl_path)
    if path and "-----" in path:
        raise ValueError("Should probably be text, not path")

    # TODO: missing: version, expired
    cmd = [
        openssl_path,
        'x509',
        '-noout',
        '-subject',
        '-issuer',
        '-startdate',
        '-enddate',
        '-serial',
    ]
    if path:
        cmd += ['-in', path]
        success, message = execute_cmd(cmd)
    else:
        success, message = execute_cmd(cmd, text)

    return success, message


def decode_hex_utf8(he):
    """Decode UTF-escaped strings in either
        \\C3\\96
        or
        \\xC3\\x96
        format
    """

    b = bytearray(len(he))
    i = 0

    s = he
    while len(s) > 0:
        m = None
        if s.startswith('\\'):
            if s.startswith('\\x'):
                m = re.match(r'\\x([a-zA-Z0-9]{2,2})', s)
            else:
                m = re.match(r'\\([a-zA-Z0-9]{2,2})', s)
        if m:
            char_code = int(m.groups()[0], 16)
            b[i] = char_code
            s = s[m.span()[1]:]
        else:
            b[i] = ord(s[0])
            s = s[1:]
        i += 1
    try:
        ret = b.decode('utf-8')
    except UnicodeDecodeError:
        log.warning("Couldn't decode hex utf-8 string: '{}'".format(he))
        return he
    if '\x00' in ret:
        return ret[:ret.index('\x00')]
    return ret


if __name__ == "__main__":
    pass