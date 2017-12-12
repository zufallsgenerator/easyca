import json
import os
import math
import string


C_RED = "\x1b[31m"
C_YELLOW = "\x1b[33m"
C_RESET = "\x1b[0m"


def get_term_width():
    # TODO: caching?
    rows, columns = os.popen('stty size', 'r').read().split()

    return int(columns)


def get_col_widths(l):
    widths = {}

    term_width = get_term_width() - 1
    keys = sorted(l[0].keys())

    max_widths = dict(zip(keys, len(keys) * [0]))

    for item in l:
        for key, value in item.items():
            max_widths[key] = max(
                max_widths[key],
                value and len(str(value)) or 0
            )

    w_each = math.floor((term_width - len(keys) + 1) / 1.0 / len(keys))
    total_width = term_width
    for key in keys:
        width = max(len(key), min(w_each, max_widths[key]))
        widths[key] = width
        total_width -= 1

    changed = True
    while(total_width and changed):
        changed = False
        for key in keys:
            if total_width == 0:
                continue
            if widths[key] < max_widths[key]:
                widths[key] += 1
                total_width -= 1
                changed = True

    return widths


def header_formatter_capwords(header):
    return string.capwords(camel_case_to_underscored(header).replace("_", " "))


def camel_case_to_underscored(text):
    ret = []
    last_was_upper = text[0].isupper()
    first_letter = True
    for l in text:
        if not l.isalpha():
            ret.append(l)
            continue
        if l.isupper() and not first_letter and not last_was_upper:
            ret.append('_' + l)
        else:
            ret.append(l)
        first_letter = False
        last_was_upper = l.isupper()

    return "".join(ret).lower()


def print_dict(d, level=0):
    pad = "    " * level
    for key, value in d.items():
        header = header_formatter_capwords(key)
        if type(value) is dict:
            print(pad + header)
            print_dict(value, level=level + 1)
        elif type(value) in (list, tuple):
            print(pad + header)
            print_dict_list(value, level=level + 1)
        else:
            if type(value) is str and '\n' in value:
                print(pad + header + ":")
                for idx, line in enumerate(value.splitlines()):
                    print(pad + "     " + line)
            else:
                print(pad + header + ": " + str(value))


def print_dict_list(l, level=0):
    pad = "    " * level
    for value in l:
        if type(value) is dict:
            print_dict(value, level=level + 1)
            print("")
        elif type(value) is list:
            print_dict_list(value, level=level + 1)
        else:
            print(pad + str(value))


def print_list(l, keys=None, header_formatter=None, field_formatters=None):
    """Output a list of dicts with headers.

    By default keys are formatted alphabetically and a default header formatter
    (_ to space, capwords) is provided.

    :param keys: provide your own key oder
    :param header_formatter: set if you want another custom for the headers
    """
    def get_formatter(key):
        if field_formatters:
            f = field_formatters.get(key)
            if f:
                return f
        return str

    if len(l) == 0:
        print("(empty)")
        return

    if not keys:
        keys = sorted(l[0].keys())

    widths = get_col_widths(l)

    if not header_formatter:
        header_formatter = header_formatter_capwords

    tpl = ' '.join(['{' + key + ':<' + str(widths[key]) + '}' for key in keys])
    header = tpl.format(
        **dict(zip(keys, [header_formatter(k)[:widths[k]] for k in keys]))
    )
    print(header)
    print('-' * len(header))

    item_tpl = dict(zip(keys, [''] * len(keys)))

    for item in l:
        safe_item = dict(item_tpl.items())
        for key in keys:
            if item.get(key) is not None:
                fmt = get_formatter(key)
                as_str = fmt(item[key])
                w = widths[key]
                if len(as_str) > w and w > 1:
                    as_str = as_str[:w - 1] + u"\u2026"
                else:
                    as_str = as_str[:w]

                safe_item[key] = as_str
        print(tpl.format(**safe_item))

if __name__ == "__main__":
    for word in [
            "helloWorld",
            "HelloWorld",
            "iDontKnow",
            "showMeYourID",
            "doYouHaveADD"
    ]:
        underscored = camel_case_to_underscored(word)
        print("{} -> {}".format(word, underscored))
