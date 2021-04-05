"""
Implement functionality for several DNS based mail-security tests.

TODO:
    - Get subdomains and check for MX records
"""

from collections import defaultdict
from typing import Mapping, Union, Any, Optional
from ipaddress import IPv6Address

import json

import requests


BASE_URL = "https://dns.google/resolve?"

class RecordNotFoundError(Exception):
    def __init__(self, msg: str):
        super().__init__(msg)

class InvalidDataError(Exception):
    def __init__(self, msg: str):
        super().__init__(msg)

class DmarcEntry:
    """
    Represents DMARC information for a domain.

    Objects of this class have attributes v, pct, ruf, rua, p, sp, adkim, aspf
    set automatically by updating self.__dict__ so this will break typing.
    You will have to use "# type: ignore" and assertions to avoid warnings.
    """

    def __init__(self, dmarc_str: str):
        """
        Construct a DmarcEntry.

        Args:
            dmarc_str (str): DMARC TXT record
        """

        self.__dict__.update(self.parse_dmarc_str(dmarc_str))

    @staticmethod
    def parse_dmarc_str(dmarc_str: str) -> defaultdict[str, Optional[str]]:
        """
        Get a defaultdict with the DMARC keys set according to a given DMARC
        string (TXT record).

        Args:
            dmarc_str (str): DMARC TXT record

        Returns:
            defaultdict: mapping for DMARC keys
        """

        mapping: defaultdict[str, Optional[str]] = defaultdict(lambda: None)

        for part in dmarc_str.strip("\"").split(";"):
            if not part: continue
            k, v = part.split("=")
            mapping[k.strip()] = v.strip()

        return mapping


def get_records(domain: str, type_: str) -> list[Mapping[str, str]]:
    res = requests.get(f"{BASE_URL}name={domain}&type={type_}")  # type: ignore

    res_json = json.loads(res.content)

    return res_json["Answer"]


def get_spf_data(domain: str) -> str:
    try:
        records = [e for e in get_records(domain, "TXT")
                   if e["data"].startswith("\"v=spf1")]
    except KeyError:
        raise RecordNotFoundError(f"No TXT records found for {domain}")

    if len(records) < 1:
        raise RecordNotFoundError(f"No SPF found for {domain}")

    spf_data = records.pop()["data"]

    return spf_data


def parse_spf_data(spf_str: str) -> defaultdict[str, list[str]]:
    res: dict[str, list[str]] = defaultdict(lambda: [])

    for entry in [e for e in spf_str.split(" ") if ":" in e]:
        type_, val = entry.split(":", 1)
        res[type_].append(val)

    return res


def walk_spf(domain: str) -> Mapping[str, list[Any]]:
    """
    Recursively walk through SPF record for a given domain.

    Obtain SPF information for a given domain and recursively request information
    of included lists (SPF "include:...") and parse a nested dict.

    Args:
        domain (str): domain to check

    Returns:
        dict: nested dictionary with all domains/IPs authorized (according to SPF)
              to send emails for the given domain.
    """

    res: Mapping[str, list[Union[Mapping[str, list[object]], str]]] = {domain: []}

    spf_data = get_spf_data(domain).strip("\"")
    entries = parse_spf_data(spf_data)

    for include in entries["include"]:
        res[domain].append(walk_spf(include))

    for entry in entries["ip6"] + entries["ip4"] + entries["a"]:
        res[domain].append(entry)

    return res


def get_dmarc(domain: str) -> DmarcEntry:
    try:
        res = get_records(f"_dmarc.{domain}", "TXT")
    except KeyError:
        raise RecordNotFoundError(f"No DMARC record found for {domain}")

    if len(res) < 1:
        msg = f"DMARC subdomain for {domain} exists but has not TXT record"
        raise RecordNotFoundError(msg)

    if len(res) > 1:
        raise InvalidDataError(
            f"found {len(res)} TXT records for _dmarc.{domain},"\
            f"this is weird... "
        )

    dmarc_data = res.pop()["data"]

    return DmarcEntry(dmarc_data)


def get_mx_record(domain: str) -> list[tuple[int, str]]:
    """
    Get MX records for a given domain.

    Args:
        domain (str): domain to get MX records for

    Returns:
        list[tuple[int, str]]: list of tuples of containing the priority and
                               the address of the MX entries
    """

    res = get_records(domain, "MX")

    if not res:
        raise RecordNotFoundError(f"No MX record found for {domain}")

    return [
        (int(e["data"].split(" ", 2)[0]),
         e["data"].split(" ", 2)[1].strip(".")) 
        for e in res
    ]


def get_a_record(domain: str) -> list[str]:
    try:
        res = get_records(domain, "A")
    except KeyError:
        raise RecordNotFoundError(f"No A record found for {domain}")

    return [e["data"].strip(".") for e in res]


def get_aaaa_record(domain: str) -> list[str]:
    try:
        res = get_records(domain, "AAAA")
    except KeyError:
        raise RecordNotFoundError(f"No AAAA record found for {domain}")

    return [e["data"].strip(".") for e in res]


def reverse_ipv4_lookup(ip: str):
    addr = f"{'.'.join([ip.split('.')[-i - 1] for i in range(4)])}.in-addr.arpa"

    try:
        res = get_records(addr, "PTR")
    except KeyError:
        raise RecordNotFoundError(f"No PTR record found for {addr}")

    return [e["data"].strip(".") for e in res]


def reverse_ipv6_lookup(ip: str):
    ip_exploded = IPv6Address(ip).exploded
    rev = '.'.join([
        ip_exploded.replace(':', '')[-i - 1]
        for i in range(len(ip_exploded.replace(':', '')))
    ])

    addr = f"{rev}.ip6.arpa"

    try:
        res = get_records(addr, "PTR")
    except KeyError:
        raise RecordNotFoundError(f"No PTR record found for {addr}")

    return [e["data"].strip(".") for e in res]


def get_mail_from_soa(domain: str):
    res = get_records(domain, "SOA")
    
    assert len(res) == 1
    
    return res.pop()["data"].split(" ")[1].replace(".", "@", 1)
    

if __name__ == "__main__":
    from pprint import pprint

    domain = "admin.ch"


    soa_addr = get_mail_from_soa(domain)

    addrs: set[str] = set()
    addrs.add(soa_addr)

    print(f"[*] address from SOA is {soa_addr}")
    print(f"[*] The following servers are allowed to send mails for {domain}")

    # get a list of all servers allowed to send mails (according to the SPF)
    # for the given domain
    spfs = None
    try:
        spfs = walk_spf(domain)
        pprint(spfs, indent=2)
    except RecordNotFoundError as e:
        print(f"[w] Could not get SPF information: {e}")

    print("[*] reverse IP lookups for SPF entries (first level)")

    # reverse-lookup for SPF entries
    servers = []
    if spfs:
        servers = [spf.strip(".") for spf in spfs[domain] if
                   hasattr(spf, "split") and
                   "/" not in spf]

        for s in servers:
            try:
                if ":" in s:
                    print(f"\t{s} -> {', '.join(reverse_ipv6_lookup(s))}")
                elif s.split(".").pop().isnumeric():
                    print(f"\t{s} -> {', '.join(reverse_ipv4_lookup(s))}")
            except RecordNotFoundError:
                ...

    # the "autodiscover" subdomain is needed for some Microsoft Exchange
    # features
    try:
        servers += get_a_record(f"autodiscover.{domain}")
    except RecordNotFoundError:
        ...

    # get MX entries
    print(f"[*] The following servers handle mail for {domain}")
    mx_records = get_mx_record(domain)
    for mx in mx_records:
        print(f"\t{mx[1]} (priority {mx[0]})")

    try:
        dmarc_data = get_dmarc(domain)
    except (RecordNotFoundError, InvalidDataError) as e:
        print(f"[w] Could not get DMARC information: {e}")
    else:
        assert hasattr(dmarc_data, "p")
        if dmarc_data.p == "quarantine": # type: ignore
            print("[*] non-compliant mails are quarantined")
        elif dmarc_data.p == "reject": # type: ignore
            print("[*] non-compliant mails are rejected")
        elif dmarc_data.p == "none": # type: ignore
            print(
                "[w] non-compliant mails are neither rejected nor qurantined"
            )

        if hasattr(dmarc_data, "ruf"):
            ruf_addr: str = dmarc_data.ruf.strip("mailto:") # type: ignore
            addrs.add(ruf_addr)

            msg = f"[*] forensic reports are sent to "\
                  f"{ruf_addr}" 
            print(msg) 
 
        if hasattr(dmarc_data, "rua"):
            rua_addr: str = dmarc_data.rua.split(":")[1] # type: ignore
            addrs.add(rua_addr)

            msg = f"[*] aggregated reports are sent to "\
                  f"{rua_addr}"
            print(msg) 

    print("[*] the following email addresses were found:")
    for addr in addrs:
        print(f"\t{addr}")

    print("[*] the following IPs/domains might be mail servers:")
    for server in set([s[1] for s in mx_records] + servers):
        print(f"\t{server}")