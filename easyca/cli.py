#!/usr/bin/env python

import os
import sys
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import arrow                        # noqa
from easyca.ca import CA            # noqa
from easyca.fmt import (
    print_list,
    print_dict,
)
import json


def str_to_relative_time(date_string):
    if date_string:
        return arrow.get(date_string).humanize()
    return ""


def error_exit(message):
    sys.stderr.write(message + '\n')
    sys.exit(1)


def cmd_ca(ca, args):
    cmd = args.ca
    if cmd == 'show':
        print_dict(ca.get_info())
    elif cmd == "init":
        ret = ca.initialize(dn=dict(cn=args.common_name))
        print_dict(ret)
    else:
        raise Exception("Subcommand '{}'' not implemented yet!".format(cmd))


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
        with open(args.req_path) as f:
            csr = f.read()
        ca.sign_request(csr)


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
    sub.add_parser('sign').add_argument('req_path', type=str)
    sub.add_parser('show').add_argument('req_id', type=str)
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
    parser_ca.add_argument('--common-name', type=str, default=None)

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


    # Commands
    # ca [show|init]
    # req [list|show|sign]
    # cert [list|show|revoke]


if __name__ == "__main__":
    cmd_main()
