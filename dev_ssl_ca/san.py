import re

def is_ip(name):
    if re.match(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$", name):
        return True
    return False


def is_ipv6(name):
    if re.match(r"^[0-9a-fA-F:\.]+$", name):
        return True
    return False


def is_uri(name):
    if re.match(r"^[a-z0-9]+:\/\/", name):
        return True
    return False


def is_email(name):
    return "@" in name and not is_uri(name)


def format_alt_names(alt_names):
    dns_idx = 1
    ip_idx = 1
    email_idx = 1
    uri_idx = 1

    ret = []
    for name in alt_names:
        if is_ip(name) or is_ipv6(name):
            ret.append("IP.{} = {}".format(ip_idx, name))
            ip_idx += 1
        elif is_email(name):
            ret.append("email.{} = {}".format(email_idx, name))
            email_idx += 1
        elif is_uri(name):
            ret.append("URI.{} = {}".format(uri_idx, name))
            uri_idx += 1
        else:
            ret.append("DNS.{} = {}".format(dns_idx, name))
            dns_idx += 1

    return "\n".join(ret)