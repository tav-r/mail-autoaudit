from typing import Callable
from ipaddress import AddressValueError, IPv4Address, IPv6Address

import requests


def is_ip(
    address: str,
    type_: Callable
):
    try:
        type_(address)
    except AddressValueError:
        return False
    return True


is_ipv4 = lambda address: is_ip(address, IPv4Address)
is_ipv6 = lambda address: is_ip(address, IPv6Address)


def my_ip():
    return requests.get("https://ifconfig.me").content.decode()
