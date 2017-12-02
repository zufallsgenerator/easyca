#!/usr/bin/env python3

import glob
import OpenSSL
import os
import json


def _decode_value(value):
    if type(value) is str:
        return value
    elif type(value) is bytes:
        return value.decode('utf-8')
    elif type(value) is list:
        return [_decode_value(v) for v in value]
    elif isinstance(value, OpenSSL.crypto.X509Name):
        ret = dict([
            (k.decode(), v.decode()) for (k, v)
            in value.get_components()
        ])
        return ret
    elif isinstance(value, OpenSSL.crypto.X509Extension):
        try:
            return value.__str__()
        except Exception as e:
            return "(Error: {})".format(e)
    else:
        return value


def _to_json(raw):
    ret = {}

    for key, value in raw.items():
        ret[key] = _decode_value(value)
    return ret


def load_x509(buf):
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, buf)

    extensions = []
    for i in range(0, cert.get_extension_count()):
        extensions.append(cert.get_extension(i))

    raw = dict(
        issuer=cert.get_issuer(),
        notAfter=cert.get_notAfter(),
        notBefore=cert.get_notBefore(),
        subject=cert.get_subject(),
        version=cert.get_version(),
        expired=cert.has_expired(),
        extensions=extensions,
        serial=cert.get_serial_number()
    )

    ret = _to_json(raw)
    return ret


BEGIN = "-----BEGIN"


def list_depot(path):
    files = glob.glob(os.path.join(path, "*"))
    for file in files:
        if file.endswith(".crt"):
            try:
                with open(file) as f:
                    buf = f.read()
                    ret = load_x509(buf)
                    print(ret)
            except Exception as e:
                print("Failed reading: {} -> {}".format(file, e))
        elif file.endswith(".pem"):
            with open(file) as f:
                buf = f.read()
                while BEGIN in buf:
                    start = buf.index(BEGIN)
                    try:
                        end = buf.index(BEGIN, start + len(BEGIN))
                    except ValueError:
                        buf = ""
                        continue
                    part = buf[start:end]
                    buf = buf[end:]
                    ret = load_x509(part)
                    print(json.dumps(ret, indent=4))





if __name__ == "__main__":
    import sys
    list_depot(sys.argv[1])
