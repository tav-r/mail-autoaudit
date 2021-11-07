from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.message import Message

from .helpers import randstr, get_conn


msg = "This email was sent as part of an email infrastructure audit."\
      "If you you receive this email, please send a screenshot "\
      "(including the subject) to ???"


def fake_from(host: str, port: int, rcpt_to: str, sender_host: str):
    conn = get_conn(host, port, sender_host)
    conn.sendmail(
        f"{randstr(5)}@{sender_host}",
        rcpt_to,
        f"From: {randstr(5)}@{randstr(30)}.com\r\n" +
        "Subject: [Pentest] Fake 'From:'\r\n" +
        msg
    )


def send_attachment(
    host: str,
    port: int,
    rcpt_to: str,
    sender_host: str,
    attachment: Message
):
    sender = f"{randstr(5)}@{sender_host}"
    msg = MIMEMultipart()
    msg["From"] = sender
    msg["Subject"] = "[Pentest] Eicar test"
    msg.attach(attachment)

    conn = get_conn(host, port, sender_host)

    conn.sendmail(sender, rcpt_to, msg.as_string())


def send_eicar(
    host: str,
    port: int,
    rcpt_to: str,
    sender_host: str,
):
    # this is xored to prevent your AV from popping the script
    eicar_xor = b"\xd8\xb5\xcf\xa1\xd0\xa5\xc0\xc1\xd0\xdb\xb4"\
                b"\xdc\xd0\xda\xd8\xb5\xb4\xa8\xd0\xde\xa9\xb7"\
                b"\xc3\xc3\xa9\xb7\xfd\xa4\xc5\xc9\xc3\xc1\xd2"\
                b"\xad\xd3\xd4\xc1\xce\xc4\xc1\xd2\xc4\xad\xc1"\
                b"\xce\xd4\xc9\xd6\xc9\xd2\xd5\xd3\xad\xd4\xc5"\
                b"\xd3\xd4\xad\xc6\xc9\xcc\xc5\xa1\xa4\xc8\xab"\
                b"\xc8\xaa"

    return send_attachment(
        host,
        port,
        rcpt_to,
        sender_host,
        MIMEText("".join([chr(b ^ 0x80) for b in eicar_xor]))
    )
