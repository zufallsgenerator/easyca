DEFAULT_CONF_ARGS = dict(
    C='c',
    ST='st',
    L='l',
    O='o',
    OU='ou',
    CN='cn',
    emailAddress='email',
)


def make_name_section(dn):
    """Create the section for distinguished name to be included in the
    openssl conf file.

    :param dn: a dict with the following keys
    - c - Country Code (two letters)
    - st - State or Province
    - l - Locality
    - o - Organization Name
    - ou - Organizational Unit Name
    - cn - Common Name
    - email - email address
    :return: a string containing the distinguished name elements
    """
    dn_str = ""
    for conf_key, arg_key in DEFAULT_CONF_ARGS.items():
        if dn and dn.get(arg_key):
            dn_str += "{} = {}\n".format(conf_key, dn.get(arg_key))
    return dn_str

__all__ = ['make_name_section']
