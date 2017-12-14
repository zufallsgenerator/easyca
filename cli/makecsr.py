#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK
import logging
import os
import sys

import arrow

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from easyca import core             # noqa
from easyca.exceptions import (     # noqa
    DuplicateRequestError,          # noqa
    OpenSSLError,                   # noqa
)
from easyca.fmt import (            # noqa
    print_dict,                     # noqa
    print_list,                     # noqa
)

from cli.shared import (                      # noqa
    add_distinguished_name_arguments,         # noqa
    build_distinguished_name_from_arguments,  # noqa
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


def cmd_make_request(out=None, dn=None, san=None, inkey=None):
    print("alt_names: {}".format(san))
    ret = core.create_request(
        dn=dn, output_folder=out, alt_names=san, inkey=inkey)
    print("Created: ")
    print("  Certificate Signing Request: {}".format(ret['csr_path']))
    if 'key_path' in ret:
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
        '--key',
        type=str,
        dest='key',
        default=None,
        help='Existing file to use as key'
    )
    parser.add_argument(
        '--csrout',
        type=str,
        dest='out',
        default=None,
        help='Path (file) to output CSR to'
    )
    add_distinguished_name_arguments(parser)
    parser.add_argument(
        '--san',
        action='append',
        help='Subject Alternative Name, DNS or IP',
    )

    args = parser.parse_args()
    san = []
    if args.san:
        for name in args.san:
            if "," in name:
                san += [part.strip() for part in name.split(",")]
            else:
                san.append(name)

    cmd_make_request(
        out=args.out,
        dn=build_distinguished_name_from_arguments(args),
        san=san,
        inkey=args.key,
    )


if __name__ == "__main__":
    cmd_main()
