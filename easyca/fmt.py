import os
import math
import string


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
    return string.capwords(header.replace("_", " ").format(string.capwords))


def print_list(l, keys=None, header_formatter=None):
    """Output a list of dicts with headers.

    By default keys are formatted alphabetically and a default header formatter
    (_ to space, capwords) is provided.

    :param keys: provide your own key oder
    :param header_formatter: set if you want another custom for the headers
    """
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
                as_str = str(item[key])
                w = widths[key]
                if len(as_str) > w and w > 1:
                    as_str = as_str[:w - 1] + u"\u2026"
                else:
                    as_str = as_str[:w]

                safe_item[key] = as_str
        print(tpl.format(**safe_item))
