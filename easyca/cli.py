#!/usr/bin/env python3
import logging
import os
import sys

import arrow

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from easyca.ca import (             # noqa
    CA,                             # noqa
    DuplicateRequestError           # noqa
)
from easyca.fmt import (            # noqa
    print_dict,                     # noqa
    print_list,                     # noqa
)

CMD_NAME = 'ca'


DEBUG = True

logging.getLogger().setLevel(logging.DEBUG if DEBUG else logging.CRITICAL)

DN_MAPPING = dict(
    c=['country'],
    st=['state', 'province'],
    l=['locality'],
    o=['org_name'],
    ou=['org_unit'],
    cn=['common_name'],
    email=['email_address']
)


FileReadErrors = (FileNotFoundError, IsADirectoryError, PermissionError)


DEFAULT_COMMON_NAME = "EasyCA Root CA (Self-Signed)"


def str_to_relative_time(date_string):
    if date_string:
        return arrow.get(date_string).humanize()
    return ""


def error_exit(message):
    sys.stderr.write(message + '\n')
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


def cmd_ca(ca, args):
    cmd = args.ca
    if cmd == 'show':
        print_dict(ca.get_info())
    elif cmd == "init":
        dn = build_distinguished_name(args)
        if not dn.get('cn'):
            dn['cn'] = DEFAULT_COMMON_NAME
        ret = ca.initialize(dn)
        print_dict(ret)
    else:
        raise Exception("Subcommand '{}'' not implemented yet!".format(cmd))


def cmd_updatedb(ca):
    ca.updatedb()


def cmd_cert(ca, args):
    cmd = args.cert
    if cmd == 'list':
        certs = ca.list_certificates()
        print_list(
            certs,
            keys=[
                'id',
                'name',
                'status',
                'revoked',
                'revoked_reason',
                'expires'
            ],
#            headers={
#                'revoked_reason': 'Reason'
#            }
            field_formatters={
                'expires': str_to_relative_time,
                'revoked': str_to_relative_time,
            },
        )
    elif cmd == 'show':
        try:
            cert = ca.get_certificate(args.cert_id)
        except LookupError:
            error_exit("Certificate with id '{}' not found.".format(
                args.cert_id))
        print_dict(cert)

    elif cmd == 'revoke':
        res = ca.revoke_certificate(args.cert_id)
        print("Result of revoking: {}".format(res))


def cmd_req(ca, args):
    cmd = args.req
    if cmd == 'list':
        certs = ca.list_requests()
        print_list(
            certs,
            field_formatters={'last_modified': str_to_relative_time})
    elif cmd == 'show':
        try:
            req = ca.get_request(args.req_id)
        except LookupError:
            error_exit("Request with id '{}' not found".format(args.req_id))
        print_dict(req)
    elif cmd == 'sign':
        try:
            with open(args.req_path) as f:
                csr = f.read()
        except FileReadErrors as e:
            error_exit("Error trying to read file: {}: {}".format(
                e.strerror,
                e.filename,
            ))
        try:
            ca.updatedb()
        except Exception as e:
            error_exit(
                "In preparation for signing a request, "
                "updatedb operation failed: {}".format(e))
        try:
            if args.days:
                ca.sign_request(csr, days=args.days)
            else:
                ca.sign_request(csr)
        except ValueError as e:
            error_exit("Failed signing request: {}".format(e))
        except DuplicateRequestError as e:
            req_dn = ca.get_request_name_from_path(args.req_path)
            error_exit(
                'A valid certificate with the DISTINGUISHED NAME already '
                'exists in the CA database.\n'
                'If it\'s expired, run \'{cmd} updatedb\' '
                'to mark it as expired in the database.\n'
                'You can also revoke it with '
                '\'{cmd} cert revoke <request serial>\' '
                '.\n'
                'Distinguished Name: {dn}'.format(
                    cmd=CMD_NAME, dn=req_dn))


def add_parser_cert(parent_parser):
    parser = parent_parser.add_parser('cert')
    sub = parser.add_subparsers(dest='cert')

    sub.add_parser('list')
    sub.add_parser('show').add_argument('cert_id', type=str)
    sub.add_parser('revoke').add_argument('cert_id', type=str)
    return parser


def add_parser_req(parent_parser):
    parser = parent_parser.add_parser('req')
    sub = parser.add_subparsers(dest='req')
    sub.add_parser('list')
    sub_sign = sub.add_parser('sign')
    sub_sign.add_argument(
        'req_path',
        metavar='<request path>',
        type=str
    )
    sub_sign.add_argument(
        '--days',
        metavar='<validity in days>',
        type=int
    )

    sub.add_parser('show').add_argument(
        'req_id',
        metavar='<request id>',
        type=str,
    )
    return parser


def cmd_main():
    import argparse
    parser = argparse.ArgumentParser(
        description='EasyCA command line interface',
    )
    parser.add_argument(
        '--ca-path',
        type=str,
        dest='ca_path',
        default=None,
        help='Path to use as CA repository. '
             'Can be omitted if env variable CA_PATH is set'
    )

    subparsers = parser.add_subparsers(
        help='command',
        dest='cmd')

    # Certificate Authority
    parser_ca = subparsers.add_parser(
        'ca',
        description='Initialize or show information about the root CA')
    parser_ca.add_argument('ca', type=str, choices=['init', 'show'])
    for key, names in DN_MAPPING.items():
        dests = ['--' + key] + ['--' + n.replace('_', '-') for n in names]
        parser_ca.add_argument(*dests, type=str, default=None)
#        parser_ca.add_argument('--common-name', type=str, default=None)

    subparsers.add_parser(
        'updatedb',
        description='Updates the database index to purge expired certificates',
    )

    # Handle CSR
    parser_req = add_parser_req(subparsers)

    # Handle signed certificates
    parser_cert = add_parser_cert(subparsers)

    args = parser.parse_args()
    if not args.cmd:
        parser.print_usage()

    if args.ca_path is not None:
        ca_path = args.ca_path
    elif os.environ.get('CA_PATH'):
        ca_path = os.environ.get('CA_PATH')
    else:
        sys.stderr.write(
            'Error: Missing path to CA.\n'
            'Use option --ca-path or env CA_PATH.\n\n')
        sys.exit(1)

    ca = CA(ca_path)

    if args.cmd == 'ca':
        cmd_ca(ca, args)

    if args.cmd == 'cert':
        if not args.cert:
            parser_cert.print_usage()
            sys.exit(1)
        cmd_cert(ca, args)

    if args.cmd == 'req':
        if not args.req:
            parser_req.print_usage()
            sys.exit(1)
        cmd_req(ca, args)

    if args.cmd == 'updatedb':
        cmd_updatedb(ca)


if __name__ == "__main__":
    cmd_main()
