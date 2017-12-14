#!/usr/bin/env python3

DN_MAPPING = dict(
    c=['country'],
    st=['state', 'province'],
    l=['locality'],
    o=['org_name'],
    ou=['org_unit'],
    cn=['common_name'],
    email=['email_address']
)


def build_distinguished_name_from_arguments(args):
    """Build a distinguished name name argument from arguments
    supplied by :py:ref: add_distinguished_name_arguments.
    :param args: from ArgumentParser
    """
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


def add_distinguished_name_arguments(parser):
    """Add arguments for distinguished name.
    :param parser: ArgumentParser instance
    """
    for key, names in DN_MAPPING.items():
        dests = ['--' + key] + ['--' + n.replace('_', '-') for n in names]
        required = (key == 'cn')
        parser.add_argument(
            *dests,
            type=str,
            default=None,
            required=required,
        )
