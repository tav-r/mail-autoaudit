# from typing import Iterator

from typing import Dict, List
from functools import reduce
from .helpers import resolve
from ..tcp_ip.helpers import is_ipv4, is_ipv6


def quantified(mechanism: str) -> List[str]:
    return [f"{sign}{mechanism}" for sign in ["~", "+", "-", "?"]]


def add_quantified_for_all(mechanisms: List[str]) -> List[str]:
    return reduce(
        lambda x, y: x + quantified(y),
        mechanisms,
        mechanisms
    )


def is_spf_entry(entry: str):
    mechanisms_quantified = add_quantified_for_all(
        ["ip4", "ip6", "a", "include"]
    )

    return entry.split(":")[0] in mechanisms_quantified and\
        ":" in entry


def retrieve_spf_records(domain: str):
    return filter(
        lambda s: s.startswith("v=spf1 "),
        resolve(domain, "TXT")
    )


def parse_record_entry(entry: str):

    def resolve_or_empty(addr: str, record_type: str) -> List[str]:
        try:
            return resolve(addr, record_type)
        except ValueError:
            return []

    type_, addr = entry.split(":", 1)

    resolve_mechanisms_quantified = add_quantified_for_all(["a", "mx"])
    recurse_mechanisms_quantified = add_quantified_for_all(["include"])
    return_mechanisms_quantified = add_quantified_for_all(["ip4", "ip6"])

    if type_ in return_mechanisms_quantified:
        return {type_: addr}

    if type_ in recurse_mechanisms_quantified:
        return {type_: {addr: list(spf_record(addr))}}

    if type_ in resolve_mechanisms_quantified:
        if type_ == "a":
            return {
                type_ : {
                    addr: resolve_or_empty(addr, "A") 
                        + resolve_or_empty(addr, "AAAA")
                }
            }

        if type_ == "mx":
            return {type_: {addr: resolve_or_empty(addr, "MX")}}

    return dict()


def spf_record(domain: str):
    spf_parts = (entry for record in (
        s.split(" ") for s in retrieve_spf_records(domain)
    ) for entry in record)

    return [parse_record_entry(e) for e in filter(
        is_spf_entry,
        spf_parts
    )]
