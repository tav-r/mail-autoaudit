# from typing import Iterator

from typing import Dict, List
from functools import reduce
from .helpers import resolve


def flatten_dict_list(dict_list: List[Dict[object, object]])\
    -> Dict[object, object]:
    # get a set of all keys for all dicts in the given list
    keys = set(reduce(
        lambda x, y: x + y,
        [list(d.keys()) for d in dict_list],
        [])
    )

    # collect all values from all dicts in the given list for each key
    return {
        key: reduce(
        lambda x, y: x + [y],
        [d[key] for d in dict_list if key in d.keys()],
        [])
    for key in keys}


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
        ["ip4", "ip6", "a", "include", "mx"]
    )

    return entry.split(":")[0] in mechanisms_quantified


def retrieve_spf_records(domain: str):
    return filter(
        lambda s: s.startswith("v=spf1 "),
        resolve(domain, "TXT")
    )


def parse_record_entry(domain: str, entry: str):

    def resolve_or_empty(addr: str, record_type: str) -> List[str]:
        try:
            return resolve(addr, record_type)
        except ValueError:
            return []

    if ":" in entry:
        type_, addr = entry.split(":", 1)
    else: 
        # if no value is specified, the domain itself is the value
        type_, addr = entry, domain

    # each mechanism can have a quantifier +, -, ? or ~
    resolve_mechanisms_quantified = add_quantified_for_all(["a", "mx"])
    recurse_mechanisms_quantified = add_quantified_for_all(["include"])
    return_mechanisms_quantified = add_quantified_for_all(["ip4", "ip6"])

    if type_ in return_mechanisms_quantified:
        return {type_: addr}

    if type_ in recurse_mechanisms_quantified:
        # recursively parse the SPF record of the included domain
        return {type_: {addr: spf_record(addr)}}

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

    return flatten_dict_list([parse_record_entry(domain, e) for e in filter(
        is_spf_entry,
        spf_parts
    )])
