from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.message import Message
from functools import partial

from .helpers import randstr, get_conn


# these are xored to prevent your AV from popping the script
eicar_zip_xor = b"\xd0\xcb\x83\x84\x8a\x80\x80\x80\x80\x80\xdb\x8a\xea\xd3["\
                b"\xabP\x9d\xc5\x80\x80\x80\xc5\x80\x80\x80\x89\x80\x9c\x80"\
                b"\xe5\xe9\xe3\xe1\xf2\xae\xf4\xf8\xf4\xd5\xd4\x89\x80\x83m"\
                b"\x8f\x0b\xe1m\x8f\x0b\xe1\xf5\xf8\x8b\x80\x81\x84h\x83\x80"\
                b"\x80\x84h\x83\x80\x80\xd8\xb5\xcf\xa1\xd0\xa5\xc0\xc1\xd0"\
                b"\xdb\xb4\xdc\xd0\xda\xd8\xb5\xb4\xa8\xd0\xde\xa9\xb7\xc3"\
                b"\xc3\xa9\xb7\xfd\xa4\xc5\xc9\xc3\xc1\xd2\xad\xd3\xd4\xc1"\
                b"\xce\xc4\xc1\xd2\xc4\xad\xc1\xce\xd4\xc9\xd6\xc9\xd2\xd5"\
                b"\xd3\xad\xd4\xc5\xd3\xd4\xad\xc6\xc9\xcc\xc5\xa1\xa4\xc8"\
                b"\xab\xc8\xaa\x8a\xd0\xcb\x81\x82\x9e\x83\x8a\x80\x80\x80"\
                b"\x80\x80\xdb\x8a\xea\xd3[\xabP\x9d\xc5\x80\x80\x80\xc5"\
                b"\x80\x80\x80\x89\x80\x98\x80\x80\x80\x80\x80\x81\x80\x80"\
                b"\x80$\x01\x80\x80\x80\x80\xe5\xe9\xe3\xe1\xf2\xae\xf4\xf8"\
                b"\xf4\xd5\xd4\x85\x80\x83m\x8f\x0b\xe1\xf5\xf8\x8b\x80\x81"\
                b"\x84h\x83\x80\x80\x84h\x83\x80\x80\xd0\xcb\x85\x86\x80\x80"\
                b"\x80\x80\x81\x80\x81\x80\xcf\x80\x80\x80\x08\x80\x80\x80"\
                b"\x80\x80"


eicar_xor = b"\xd8\xb5\xcf\xa1\xd0\xa5\xc0\xc1\xd0\xdb\xb4\xdc\xd0\xda\xd8"\
            b"\xb5\xb4\xa8\xd0\xde\xa9\xb7\xc3\xc3\xa9\xb7\xfd\xa4\xc5\xc9"\
            b"\xc3\xc1\xd2\xad\xd3\xd4\xc1\xce\xc4\xc1\xd2\xc4\xad\xc1\xce"\
            b"\xd4\xc9\xd6\xc9\xd2\xd5\xd3\xad\xd4\xc5\xd3\xd4\xad\xc6\xc9"\
            b"\xcc\xc5\xa1\xa4\xc8\xab\xc8\xaa"


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


send_eicar = partial(
    send_attachment,
    attachment=MIMEText("".join(chr(b ^ 0x80) for b in eicar_xor))
)


send_zipped_eicar = partial(
    send_attachment,
    attachment=MIMEText("".join(chr(b ^ 0x80) for b in eicar_xor))
)
