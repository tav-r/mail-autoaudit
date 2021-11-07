# from typing import Iterator

from .helpers import resolve


def is_spf_entry(entry: str):
    return entry.split(":")[0] in ["ip4", "ip6", "a", "include"] and\
        ":" in entry


def parse_record_entry(entry: str):
    type_, addr = entry.split(":", 1)

    if type_ in ["ip4", "ip6"]:
        return addr

    if type_ == "include":
        return {addr: list(spf_record(addr))}

    if type_ == "a":
        return {addr: resolve(addr, "A")}


def spf_record(domain: str):
    return [parse_record_entry(e) for e in filter(
        is_spf_entry,
        (entry for record in map(
            lambda s: s.split(" "),
            filter(
                lambda s: s.startswith("v=spf1 "),
                resolve(domain, "TXT")
            )
         ) for entry in record)
    )]
