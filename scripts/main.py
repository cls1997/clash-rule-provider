import base64
import re
from enum import Enum

import yaml

DEBUG = True

comment_pattern = r'^\!|\[|^@@|^\d+\.\d+\.\d+\.\d+'
domain_pattern = r'(?:[\w\-]*\*[\w\-]*\.)?([\w\-]+\.[\w\.\-]+)[\/\*]*'
ip_pattern = r'\b\d{0,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'

comment_re = re.compile(comment_pattern)
ip_re = re.compile(ip_pattern)
domain_re = re.compile(domain_pattern)


class LineType(Enum):
    COMMENT = "This is comment line."
    DOMAIN = "Find a domain line."
    IP = "Find a IP line."
    OTHER = "Not matches any line type."


def fetch_gfwlist():
    with open("../gfwlist/gfwlist.txt", "rb") as _gfwlist:
        _content = _gfwlist.read()
        return base64.decodebytes(_content).decode('utf-8')


def log_line(line: str, line_type: LineType):
    if DEBUG:
        print(line_type.value, line)


def parse_line(line: str):
    result = None
    line_type = LineType.OTHER
    if comment_re.match(line):
        line_type = LineType.COMMENT
    elif domain_re.match(line):
        result = domain_re.findall(line)[0]
        if ip_re.match(line):
            line_type = LineType.IP
        else:
            line_type = LineType.DOMAIN
    else:
        pass
    log_line(line, line_type)
    return result, line_type


def process_gfwlist(gfw_list):
    domain_set = set()
    ip_set = set()
    actions = {
        LineType.DOMAIN: lambda x: domain_set.add(x),
        LineType.IP: lambda x: ip_set.add(x)
    }

    for item in gfw_list:
        result, line_type = parse_line(item)
        if result:
            actions.get(line_type)(result)

    return domain_set, ip_set


if __name__ == '__main__':
    gfwlist = fetch_gfwlist()
    domain_set, ip_set = process_gfwlist(gfwlist.splitlines())
    out = dict(payload=["DOMAIN-SUFFIX," + x for x in domain_set])
    with open("../gfwlist.yml", 'w') as file:
        file.write(yaml.dump(out))
