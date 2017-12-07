#!/usr/bin/env python

import os
import sys
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from easyca.ca import CA            # noqa
from easyca.fmt import print_list   # noqa


def cmd_ca(ca, args):
    cmd = args.ca
    if cmd == 'show':
        print(ca.get_info())
    elif cmd == "init":
        ret = ca.initialize()
        print(ret)
    else:
        raise Exception("Subcommand '{}'' not implemented yet!".format(cmd))


def cmd_cert(ca, args):
    cmd = args.cert
    if cmd == 'list':
        certs = ca.list_certificates()
        print_list(certs, ['id', 'name', 'status', 'revoked', 'expires'])
    elif cmd == 'show':
        print(ca.get_certificate(args.cert_id))


def cmd_req(ca, args):
    cmd = args.req
    if cmd == 'list':
        certs = ca.list_requests()
        print_list(certs)
    elif cmd == 'show':
        print(ca.get_request(args.req_id))


def add_parser_cert(parent_parser):
    parser = parent_parser.add_parser('cert')
    sub = parser.add_subparsers(dest='cert')
    sub.add_parser('list')
    sub.add_parser('show').add_argument('cert_id', type=str)
    sub.add_parser('revoke')


def add_parser_req(parent_parser):
    parser = parent_parser.add_parser('req')
    sub = parser.add_subparsers(dest='req')
    sub.add_parser('list')
    sub.add_parser('sign')
    sub.add_parser('show').add_argument('req_id', type=str)


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
    parser_ca.add_argument('--common-name', type=str)

    # Handle CSR
    add_parser_req(subparsers)

    # Handle signed certificates
    add_parser_cert(subparsers)

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
        cmd_cert(ca, args)

    if args.cmd == 'req':
        cmd_req(ca, args)

#    print(args)

    # Commands
    # ca [show|init]
    # req [list|show|sign]
    # cert [list|show|revoke]


if __name__ == "__main__":
    cmd_main()
