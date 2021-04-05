from typing import List
import requests


BASE_URL = "https://api.hackertarget.com/"

def reverse_ip(ip: str) -> list[str]:
    return requests.get(
        f"{BASE_URL}/reverseiplookup/?q={ip}"
    ).content.decode().split("\n")
