"""
Module for scanning a mailserver for security misconfigurations.
"""

from smtplib import SMTPRecipientsRefused

from .helpers import randstr, get_conn


def vrfy_available(host: str, port: int, sender_host: str) -> bool:
    conn = get_conn(host, port, sender_host)
    return conn.has_extn("VRFY")


def expn_available(host: str, port: int, sender_host: str) -> bool:
    conn = get_conn(host, port, sender_host)
    return conn.has_extn("EXPN")


def is_open_relay(host: str, port: int, sender_host: str) -> bool:
    conn = get_conn(host, port, sender_host)
    try:
        conn.sendmail(
            f"{randstr(5)}@{sender_host}",
            f"{randstr(5)}@{randstr(30)}.com",
            "relayed"
        )

    except SMTPRecipientsRefused:
        return False

    return True


def optional_starttls(address: str, port: int, sender_host: str) -> bool:
    conn = get_conn(address, port, sender_host)

    return\
        200 <= conn.docmd(f"MAIL FROM: {randstr(5)}@{sender_host}")[0] < 400
