from smtplib import SMTP
from random import randint


def randstr(l: int = 30) -> str:
    return ''.join(chr(randint(ord('a'), ord('z'))) for _ in range(l))


def get_conn(host: str, port: int, sender_host: str) -> SMTP:
    conn = SMTP(host, port)
    conn.ehlo(sender_host)

    if conn.has_extn("STARTTLS"):
        conn.starttls()

    return conn
