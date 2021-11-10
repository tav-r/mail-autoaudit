from smtplib import SMTP
from random import randint

from .dns.helpers import resolve


def randstr(l: int = 30) -> str:
    return ''.join(chr(randint(ord('a'), ord('z'))) for _ in range(l))


def get_conn(host: str, port: int, sender_addr: str) -> SMTP:
    conn = SMTP(host, port)
    conn.ehlo(sender_addr.split("@").pop())

    if conn.has_extn("STARTTLS"):
        conn.starttls()

    return conn


def invalid_domain():
    while True:
        domain = f"{randstr(30)}.com"
        try:
            resolve(domain, "A")
        except ValueError:
            try:
                resolve(domain, "AAAA")
            except ValueError:
                return domain
