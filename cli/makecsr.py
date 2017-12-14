#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK
import logging
import os
import sys

import arrow

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from easyca import core
from easyca.exceptions import (
    DuplicateRequestError,          # noqa
    OpenSSLError,                   # noqa
)
from easyca.fmt import (            # noqa
    print_dict,                     # noqa
    print_list,                     # noqa
)
from cli.cmd_ca import (
    DN_MAPPING,
    distinguished_name_formatter,
)

CMD_NAME = 'csr'

C_ERROR = "\x1b[31;1m"
C_YELLOW = "\x1b[33m"
C_RESET = "\x1b[0m"


DEBUG = os.environ.get('DEBUG', '').lower() in ('true', '1')

logging.getLogger().setLevel(logging.DEBUG if DEBUG else logging.CRITICAL)


DEFAULT_COMMON_NAME = "Test Cert"


def str_to_relative_time(date_string):
    if date_string:
        return arrow.get(date_string).humanize()
    return ""


def error_exit(message):
    isatty = sys.stderr.isatty()

    if isatty:
        sys.stderr.write(C_ERROR)
    sys.stderr.write(message)
    if isatty:
        sys.stderr.write(C_RESET)
    sys.stderr.write('\n')

    sys.exit(1)


def build_distinguished_name(args):
    dn = {}
    for key, names in DN_MAPPING.items():
        for name in names:
            if hasattr(args, name):
                value = getattr(args, name)
                if value is not None:
                    dn[key] = value
                    continue
        if hasattr(args, key):
            value = getattr(args, key)
            if value is not None:
                dn[key] = value
    return dn


def cmd_make_request(out=None, dn=None, san=None):
    print("alt_names: {}".format(san))
    ret = core.create_request(dn=dn, output_folder=out, alt_names=san)
    print("Created: ")
    print("  Certificate Signing Request: {}".format(ret['csr_path']))
    print("                  Private key: {}".format(ret['key_path']))


def cmd_main():
    import argparse
    parser = argparse.ArgumentParser(
        description='EasyCA Certificate Helper',
    )
    parser.add_argument(
        '--out',
        type=str,
        dest='out',
        default='.',
        help='Folder to output csr and key to'
    )
    parser.add_argument(
        '--keyout',
        type=str,
        dest='out',
        default=None,
        help='File to output the new private key to'
    )
    parser.add_argument(
        '--csrout',
        type=str,
        dest='out',
        default=None,
        help='Path (file) to output CSR to'
    )
    for key, names in DN_MAPPING.items():
        dests = ['--' + key] + ['--' + n.replace('_', '-') for n in names]
        parser.add_argument(*dests, type=str, default=None)
    parser.add_argument(
        '--san',
        action='append',
        help='Subject Alternative Name, DNS or IP',
    )

    args = parser.parse_args()
    san = []
    for name in args.san:
        if "," in name:
            san += [part.strip() for part in name.split(",")]
        else:
            san.append(name)

    cmd_make_request(
        out=args.out, dn=build_distinguished_name(args), san=san)


if __name__ == "__main__":
    cmd_main()
