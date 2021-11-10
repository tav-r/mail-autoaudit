"""
Module for scanning a mailserver for security misconfigurations.
"""

from smtplib import SMTPRecipientsRefused

from .helpers import randstr, get_conn, invalid_domain


def vrfy_available(host: str, port: int, sender_addr: str) -> bool:
    conn = get_conn(host, port, sender_addr)
    return conn.has_extn("VRFY")


def expn_available(host: str, port: int, sender_addr: str) -> bool:
    conn = get_conn(host, port, sender_addr)
    return conn.has_extn("EXPN")


def is_open_relay(host: str, port: int, sender_addr: str) -> bool:
    conn = get_conn(host, port, sender_addr)

    try:
        conn.sendmail(
            sender_addr,
            f"{randstr(5)}@{invalid_domain()}.com",
            "relayed"
        )

    except SMTPRecipientsRefused:
        return False

    return True


def optional_starttls(address: str, port: int, sender_addr: str) -> bool:
    conn = get_conn(address, port, sender_addr)

    return\
        200 <= conn.docmd(f"MAIL FROM: {sender_addr}")[0] < 400
