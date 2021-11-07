from typing import Callable

from .helpers import resolve, reverse_lookup_ipv4, reverse_lookup_ipv6


def get_check_reverse_match(record_type: str, lookup: Callable):
    def _check_reverse_match(domain: str):
        return {mx: {ip: lookup(ip) for ip in resolve(mx, record_type)}
            for mx in map(lambda m: m.split(" ")[1], resolve(domain, "MX"))}

    return _check_reverse_match

check_ipv4_reverse_match = get_check_reverse_match("A", reverse_lookup_ipv4)
check_ipv6_reverse_match = get_check_reverse_match(
    "AAAA", reverse_lookup_ipv6
)
