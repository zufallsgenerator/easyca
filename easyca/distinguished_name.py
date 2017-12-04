

class DistinguishedName(dict):
    """Distinguished Name.

    :param c: Country/Region (two letters)
    :param cn: Common Name - hostname or dns
    :param email: Email address
    :param l: Locality
    :param o: Organization Name
    :param ou: Organizational Unit
    :param st: State or Province
    """
    def __init__(
        self,
        c=None,
        cn=None,
        email=None,
        l=None,
        o=None,
        ou=None,
        st=None,
    ):
        if not(cn):
            raise ValueError("key 'cn' is required")
        super().__init__(c=c, cn=cn, email=email, l=l, o=o, ou=ou, st=st)


_NAME_MAPPING = dict(
    C='c',
    ST='st',
    L='l',
    O='o',
    OU='ou',
    CN='cn',
    emailAddress='email',
)


def make_dn_section(dn):
    """Create the section for distinguished name to be included in the
    openssl conf file.

    :param dn: a :py:class:DistinguishedName or :py:class:dict with the
               following keys
    - c - Country Code (two letters)
    - st - State or Province
    - l - Locality
    - o - Organization Name
    - ou - Organizational Unit Name
    - cn - Common Name
    - email - email address
    :return: a string containing the distinguished name elements
    """
    if not isinstance(dn, DistinguishedName):
        dn = DistinguishedName(**dn)
    dn_str = ""
    for conf_key, arg_key in _NAME_MAPPING.items():
        if dn and dn.get(arg_key):
            dn_str += "{} = {}\n".format(conf_key, dn.get(arg_key))
    return dn_str


__all__ = [
    'DistinguishedName',
    'make_dn_section'
]
