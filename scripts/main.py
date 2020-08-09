from __future__ import annotations

import base64
import copy
import re
from enum import Enum
from typing import Tuple

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


class Context:
    def __init__(self):
        self._domain = set()
        self._ip = set()

    def ip(self) -> set:
        return copy.deepcopy(self._ip)

    def domain(self) -> set:
        return copy.deepcopy(self._domain)

    def add(self, value: str, type: LineType):
        if type is LineType.IP:
            self._ip.add(value)
        elif type is LineType.DOMAIN:
            self._domain.add(value)
        else:
            pass


class Input(object):
    def input(self, context: Context) -> Input:
        return self


class Output(object):
    def output(self, context: Context) -> None:
        pass


class FileOutput(Output):
    def __init__(self, filename: str):
        self._filename = filename

    def output(self, context: Context) -> None:
        pass


class ClashProviderRuleYml(FileOutput):
    def __init__(self, filename: str):
        super().__init__(filename)

    def output(self, context: Context) -> None:
        import ruamel.yaml
        yaml = ruamel.yaml.YAML()
        yaml.indent(sequence=4, offset=4)
        domain_set, ip_set = context.domain(), context.ip()
        out = dict(payload=["DOMAIN-SUFFIX," + x for x in domain_set])
        with open(self._filename, 'w') as file:
            yaml.dump(out, file)


class DnsmasqIpsetRuleOutput(FileOutput):
    def __init__(self, filename: str, ipset_name: str, dns: Tuple[str, int]):
        super().__init__(filename)
        self._ipset_name = ipset_name
        self._dns = dns

    def output(self, context: Context) -> None:
        import datetime
        with open(self._filename, "w") as f:
            f.write('# gfw list ipset rules for dnsmasq\n')
            f.write('# updated on ' + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + '\n')
            f.write('#\n')
            for domain in context.domain():
                f.write('server=/.%s/%s#%s\n' % (domain, self._dns[0], self._dns[1]))
                f.write('ipset=/.%s/%s\n' % (domain, self._ipset_name))


class GFWListInput(Input):
    def __init__(self, filename, encoding="utf-8"):
        self._filename = filename
        self._encoding = encoding

    @staticmethod
    def parse_line(line: str) -> (str, LineType):
        result = None
        line_type = LineType.OTHER
        if comment_re.match(line):
            line_type = LineType.COMMENT
        elif domain_re.match(line):
            result = domain_re.findall(line)[-1]
            if ip_re.match(line):
                line_type = LineType.IP
            else:
                line_type = LineType.DOMAIN
        else:
            pass
        log_line(line, line_type)
        return result, line_type

    def input(self, context: Context) -> Context:
        _result = None
        with open(self._filename, "rb") as f:
            _content = f.read()
            _result = base64.decodebytes(_content).decode(self._encoding)
        if _result:
            _result = _result.splitlines()
            for line in _result:
                result, line_type = self.parse_line(line)
                context.add(result, line_type)
        return context


def log_line(line: str, line_type: LineType):
    if DEBUG:
        print(line_type.value, line)


def main():
    context = Context()
    source = GFWListInput("../gfwlist/gfwlist.txt")
    source.input(context)
    target = ClashProviderRuleYml("../gfwlist.yml")
    target.output(context)
    target2 = DnsmasqIpsetRuleOutput("../dnsmasq.conf", "gfwlist", ("127.0.0.1", 53))
    target2.output(context)


if __name__ == '__main__':
    main()
