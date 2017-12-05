#!/usr/bin/env python3
# Get info only using openssl, no libraries

import json

from .helpers import execute_cmd


EXT_PREFIX = "X509v3 "


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
            print("in extension: {}".format(line))
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


def get_certificate_extensions_as_json(path):
    cmd = [
        'openssl',
        'x509',
        '-text',
        '-noout',
        '-certopt',
        # No linebreak between the two below here
        'no_aux,no_header,no_issuer,no_pubkey,no_serial,no_sigdump,'
        'no_signame,no_subject,no_subject,no_validity,no_version',
        '-in',
        path
    ]
    success, message = execute_cmd(cmd)
    if not success:
        return {
            'success': False,
            'message': message
        }
    if success:
        return {
            'success': True,
            'extension': parse_extensions_output(message)
        }


def get_request_extensions_as_json(path):
    cmd = [
        'openssl',
        'req',
        '-text',
        '-noout',
        '-reqopt',
        # No linebreak between the two below here
        'no_attributes,no_aux,no_header,no_issuer,no_pubkey,no_serial,'
        'no_sigdump,no_signame,no_subject,no_subject,no_validity,no_version',
        '-in',
        path
    ]
    success, message = execute_cmd(cmd)
    print(message)
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


def extract_san_from_req(path):
    san = []
    res = get_request_extensions_as_json(path)
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


def test():
    print(make_camel_case("hello you are my world"))

    extensions = parse_extensions_output("""X509v3 extensions:
            X509v3 Basic Constraints:
                CA:FALSE
            X509v3 Subject Key Identifier:
                E9:DA:74:31:41:32:A8:21:DB:24:07:BA:CC:26:46:61:D2:C1:96:02
            X509v3 Authority Key Identifier:
                keyid:6A:C4:A7:91:B5:A0:CF:01:86:A3:83:72:55:93:6C:83:3D:C7:FA:87

            X509v3 Subject Alternative Name:
                DNS:acme.org, DNS:www.acme.org, DNS:cdn1.far-away.com, IP Address:192.168.56.100""")  # noqa

    print(json.dumps(extensions, indent=4))

if __name__ == "__main__":
    import sys
    ret = get_request_extensions_as_json(sys.argv[1])

    print(json.dumps(ret, indent=4))
