# from typing import Iterator

from .helpers import resolve


def is_spf_entry(entry: str):
    return entry.split(":")[0] in ["ip4", "ip6", "a", "include"] and\
        ":" in entry


def retrieve_spf_records(domain: str):
    return filter(
        lambda s: s.startswith("v=spf1 "),
        resolve(domain, "TXT")
    )


def parse_record_entry(entry: str):
    type_, addr = entry.split(":", 1)

    if type_ in ["ip4", "ip6"]:
        return addr

    if type_ == "include":
        return {addr: list(spf_record(addr))}

    if type_ == "a":
        return {addr: resolve(addr, "A")}

    return dict()


def spf_record(domain: str):
    spf_parts = (entry for record in (
        s.split(" ") for s in retrieve_spf_records(domain)
    ) for entry in record)

    return [parse_record_entry(e) for e in filter(
        is_spf_entry,
        spf_parts
    )]
