import requests
import json

from ipaddress import IPv6Address, IPv4Address


def resolve(domain: str, type_: str) -> list[str]:
    try:
        return [
            ans["data"] for ans in
            json.loads(requests.get(
                f"https://dns.google.com/resolve?name={domain}&type={type_}"
            ).content)["Answer"]
        ]
    except KeyError:
        raise ValueError(f"Could not resolve domain '{domain}'")


def soa(domain: str) -> list[str]:
    return resolve(domain, "SOA")


def dmarc_record(domain: str) -> list[str]:
    return resolve(f"_dmarc.{domain}", "TXT")


def mx_record(domain: str) -> list[str]:
    return resolve(domain, "MX")


def reverse_lookup_ipv4(ip: str) -> list[str]:
    reversed_ipv4 = IPv4Address(ip).reverse_pointer
    return resolve(str(reversed_ipv4), "PTR")


def reverse_lookup_ipv6(ip: str) -> list[str]:
    reversed_ipv6 = IPv6Address(ip).reverse_pointer
    return resolve(str(reversed_ipv6), "PTR")
