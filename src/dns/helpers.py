import requests
import json

from ipaddress import IPv6Address


def resolve(domain: str, type_: str):
    try:
        return [
            ans["data"] for ans in
            json.loads(requests.get(
                f"https://dns.google.com/resolve?name={domain}&type={type_}"
            ).content)["Answer"]
        ]
    except KeyError:
        raise ValueError(f"Could not resolve domain '{domain}'")


def dmarc_record(domain: str):
    return resolve(f"_dmarc.{domain}", "TXT")


def mx_record(domain: str):
    return resolve(domain, "MX")


def reverse_lookup_ipv4(ip: str):
    return resolve(f"{'.'.join(ip.split('.')[::-1])}.in-addr.arpa", "PTR")


def reverse_lookup_ipv6(ip: str):
    return resolve(f"{'.'.join(IPv6Address(ip).exploded.replace(':', '')[::-1])}.ip6.arpa", "PTR")