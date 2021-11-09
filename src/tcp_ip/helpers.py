from typing import Callable
from ipaddress import AddressValueError, IPv4Address, IPv6Address
from functools import partial

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


is_ipv4 = partial(is_ip, type_=IPv4Address)
is_ipv6 = partial(is_ip, type_=IPv6Address)


def my_ip():
    return requests.get("https://ifconfig.me").content.decode()
