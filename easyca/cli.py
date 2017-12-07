#!/usr/bin/env python

import os
import sys
import math
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from easyca.ca import CA  # noqa


def get_term_width():
    # TODO: caching?
    rows, columns = os.popen('stty size', 'r').read().split()
    return int(columns)


def print_list(l, keys=None):
    if len(l) == 0:
        print("(empty)")
        return

    if not keys:
        keys = sorted(l[0].keys())

    max_width = get_term_width() - 1
    widths = {}

    w_each = math.floor((max_width - len(keys) + 1) / 1.0 / len(keys))
    for key in keys:
        widths[key] = w_each

    tpl = ' '.join(['{' + key + ':<' + str(widths[key]) + '}' for key in keys])
    header = tpl.format(
        **dict(zip(keys, [k.upper()[:widths[key]] for k in keys]))
    )
    print(header)
    print('-' * len(header))

    item_tpl = dict(zip(keys, [''] * len(keys)))

    for item in l:
        safe_item = dict(item_tpl.items())
        for key in keys:
            if item.get(key) is not None:
                as_str = str(item[key]).strip()
                w = widths[key]
                if len(as_str) > w and w > 1:
                    as_str = as_str[:w - 1] + u"\u2026"
                else:
                    as_str = as_str[:w]

                safe_item[key] = as_str
        print(tpl.format(**safe_item))


def cmd_ca(ca, args):
    cmd = args.ca
    if cmd == 'show':
        print(ca.get_info())
    elif cmd == "init":
        ret = ca.initialize()
    else:
        raise Exception("Subcommand '{}'' not implemented yet!".format(arg))


def cmd_cert(ca, args):
    cmd = args.cert
    if cmd == 'list':
        certs = ca.list_certificates()
        print_list(certs)
    elif cmd == 'show':
        print(ca.get_certificate(args.cert_id))


def cmd_req(ca, args):
    cmd = args.req
    if cmd == 'list':
        certs = ca.list_requests()
        print_list(certs)
    elif cmd == 'show':
        print(ca.get_request(args.cert_id))


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
