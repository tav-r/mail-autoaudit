"""
Implementation of serveral e-mail server security tests.

TODO:
    - Enumerate users based on username list
        - IMAP
        - SMTP
        - POP3
    - Banner grabbing
    - Check message size (should not be too large)
    - Malware checks
        - Zipped EICAR file
        - Excel sheet with macro
        - Word doc with macro
        - Dummy file with PE header
        - Dummy file with ELF header
"""

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from enum import Enum
from abc import ABC, abstractmethod
from typing import Iterator


def get_msg(rcpt_from: str, sender: str, subject: str) -> str:
    """
    Format an email message aking the receiver to send a screenshot.

    Args:
        rcpt_from (str): 'RCPT FROM:' address
        sender (str): 'From:' address (note that this may differ from
                      'rcpt_from')
        subject (str): subject of the message (used to identify test)
    """
    return f"From: {sender}\r\nSubject: {subject}\r\n"\
           f"This email was sent as part of an email infrastructure audit."\
           f"If you you receive this email, please send a screenshot "\
           f"(including the subject) to {rcpt_from}"


class ResultLevel(Enum):
    NONE = 0
    OK=1
    INFO=2
    WARNING=3


class TestResult:
    def __init__(self, test_name: str, level: ResultLevel,
                 description: str, suggestion: str):
        self.__test_name = test_name
        self.__level = level
        self.__description = description
        self.__suggestion = suggestion

    @property
    def test_name(self) -> str:
        return self.__test_name

    @property
    def level(self) -> ResultLevel:
        return self.__level

    @property
    def description(self) -> str:
        return self.__description

    @property
    def suggestion(self) -> str:
        return self.__suggestion 

    def __str__(self) -> str:
        ...


class EmailServerTest(ABC):
    def __init__(self):
        ...

    @abstractmethod
    def run(self, smtp_conn: smtplib.SMTP) -> TestResult:
        ...


class EmailServerTestSuite:
    def __init__(self, target_server: str, use_tls: bool=False,
                 target_port: int=25):
        self.__tests: list[EmailServerTest] = []
        self.__target_server = target_server
        self.__target_port = target_port
        self.__use_tls = use_tls

    def add_test(self, test: EmailServerTest):
        self.__tests.append(test)

    def run_all(self) -> Iterator[TestResult]:
        SMTP = smtplib.SMTP_SSL if self.__use_tls else smtplib.SMTP

        for test in self.__tests:
            with SMTP(self.__target_server, self.__target_port) as smtp_conn:
                yield test.run(smtp_conn)


class FakeFrom(EmailServerTest):
    def __init__(self, mail_from: str, fake_from: str, rcpt_to: str):
        self.__fake_from = fake_from
        self.__rcpt_to = rcpt_to
        self.__mail_from = mail_from

    def run(self, smtp_conn: smtplib.SMTP) -> TestResult:
        smtp_conn.sendmail(self.__mail_from,
                           self.__rcpt_to,
                           get_msg(
                               self.__mail_from,
                               self.__fake_from,
                               "'fake from'-test"
                           )
        )

        return TestResult("'Fake-From' test sent", ResultLevel.INFO,
                          f"Test mail sent to {self.__rcpt_to}, check inbox",
                          "-")


class VrfyAvailable(EmailServerTest):
    __des_found = "An attacker can enumerate users using the VRFY command"
    __des_not_found = "An attacker cannot enumerate users using the VRFY"\
                      "command"
    __suggestion = "Disable the VRFY command on the SMTP server"

    def run(self, smtp_conn: smtplib.SMTP) -> TestResult:
        smtp_conn.ehlo()
        if smtp_conn.has_extn("VRFY"):
            return TestResult("VRFY available", ResultLevel.WARNING,
                              self.__des_found, self.__suggestion)
        return TestResult("VRFY not available", ResultLevel.OK,
                          self.__des_not_found, "-")


class ExpnAilable(EmailServerTest):
    __des_found = "An attacker can enumerate users using the EXPN command"
    __des_not_found = "An attacker cannot enumerate users using the"\
                      "EXPN command"
    __suggestion = "Disable the EXPN command on the SMTP server"

    def run(self, smtp_conn: smtplib.SMTP) -> TestResult:
        smtp_conn.ehlo()
        if smtp_conn.has_extn("EXPN"):
            return TestResult("EXPN available", ResultLevel.WARNING,
                                self.__des_found, self.__suggestion)
        return TestResult("EXPN not available", ResultLevel.OK,
                            self.__des_not_found, "-")


class OpenRelay(EmailServerTest):
    __des_found = "A apammer can use this SMTP server as a relay"
    __des_not_found = "A apammer cannot use this SMTP server as a relay"
    __suggestion = "Configure the server to deny relaying for untrusted sources"

    def __init__(self, mail_from: str, test_address: str):
        """
        Construct an OpenRelay test.

        Args:
            test_addr (str): destination addres for relayed mail
            mail_from (str): sender address for relayed mail
        """

        self.__test_address = test_address
        self.__mail_from = mail_from

    def run(self, smtp_conn: smtplib.SMTP) -> TestResult:
        smtp_conn.ehlo()

        if smtp_conn.has_extn("STARTTLS"):
            smtp_conn.starttls()

        try:
            smtp_conn.sendmail(self.__mail_from, self.__test_address,
                               "Relayed message")
        except smtplib.SMTPRecipientsRefused:
            return TestResult("Not an open Relay", ResultLevel.OK,
                                self.__des_not_found, "-")
        return TestResult(
            f"Probably an open relay ('RCPT TO:<{self.__test_address}>')",
            ResultLevel.WARNING,
            self.__des_found, self.__suggestion
        )


class OptionalStarttls(EmailServerTest):
    __des_optional = "STARTTLS is supported but not required. This "\
                     "configuration is vulnerable to a downgrade attack."
    __des_no_starttls = "This server does not support STARTTLS"
    __des_enforced = "STARTTLS is required"
    __sugg_no_starttls = "Configure the server to provide STARTTLS and "\
                         "(if possible) enforce STARTTLS"
    __sugg_optional_starttls = "If possible, configure the server to enforce "\
                               "STARTTLS"
    __des_encrypted = "Encrypted SMTP connection, testing for STARTTLS is"\
                      "pointless"

    def __init__(self, mail_from: str):
        """
        Construct an OptionalStarttls test.

        Args:
            mail_from (str): sender address, used to test if STARTTLS is
                             required
        """

        self.__mail_from = mail_from

    def run(self, smtp_conn: smtplib.SMTP) -> TestResult:
        if hasattr(smtp_conn.sock, "do_handshake"):
            return TestResult("STARTTLS not tested", ResultLevel.OK,
                              self.__des_encrypted, "-")

        smtp_conn.ehlo()
        if not smtp_conn.has_extn("STARTTLS"):
            return TestResult("STARTTLS not supported", ResultLevel.WARNING,
                                self.__des_no_starttls, self.__sugg_no_starttls)
        code, _ = smtp_conn.docmd("MAIL FROM:", f"<{self.__mail_from}>")
        if 200 <= code < 400:
            return TestResult("STARTTLS optional", ResultLevel.WARNING,
                              self.__des_optional,
                              self.__sugg_optional_starttls)

        return TestResult("STARTTLS enforced", ResultLevel.OK,
                            self.__des_enforced, "-")


class SendEicar(EmailServerTest):
    # this is xored to prevent your AV from popping the script
    __eicar_xor = b"\xd8\xb5\xcf\xa1\xd0\xa5\xc0\xc1\xd0\xdb\xb4"\
                  b"\xdc\xd0\xda\xd8\xb5\xb4\xa8\xd0\xde\xa9\xb7"\
                  b"\xc3\xc3\xa9\xb7\xfd\xa4\xc5\xc9\xc3\xc1\xd2"\
                  b"\xad\xd3\xd4\xc1\xce\xc4\xc1\xd2\xc4\xad\xc1"\
                  b"\xce\xd4\xc9\xd6\xc9\xd2\xd5\xd3\xad\xd4\xc5"\
                  b"\xd3\xd4\xad\xc6\xc9\xcc\xc5\xa1\xa4\xc8\xab"\
                  b"\xc8\xaa"

    def __init__(self, mail_from: str, rcpt_to: str):
        self.__mail_from = mail_from
        self.__rcpt_to = rcpt_to

    def run(self, smtp_conn: smtplib.SMTP) -> TestResult:
        msg = MIMEMultipart()
        msg["From"] = self.__mail_from
        msg["Subject"] = "Eicar Test"
        msg.attach(MIMEText("".join([chr(b ^ 0x80) for b in self.__eicar_xor])))

        smtp_conn.starttls()

        smtp_conn.sendmail(self.__mail_from, self.__rcpt_to, msg.as_string())

        return TestResult("Eicar test sent", ResultLevel.INFO,
                          f"Test mail sent to {self.__rcpt_to}, check inbox",
                          "-")


if __name__ == "__main__":
    target_server = "mail.target.invalid"
    real_sender_addr = "pentester@hacker.invalid"
    second_sender_addr = "pentester@second.invalid"
    fake_sender_addr = "spam@spam.invalid"
    test_receive_addr = "victim@target.invalid"

    test_suite = EmailServerTestSuite(target_server)
    # test if VRFY command is available
    test_suite.add_test(VrfyAvailable())
    # test if EXPN command is available
    test_suite.add_test(ExpnAilable())
    # test if "MAIL FROM:" may differ from "From:"
    test_suite.add_test(FakeFrom(real_sender_addr, fake_sender_addr, test_receive_addr))
    # try to use server as an open realay
    test_suite.add_test(OpenRelay(real_sender_addr, second_sender_addr))
    # test if STARTTLS is available and enforced
    test_suite.add_test(OptionalStarttls(test_receive_addr))
    # send an EICAR test file as an attachment
    test_suite.add_test(SendEicar(real_sender_addr, test_receive_addr))

    for result in test_suite.run_all():
        prefix = "[i]" if result.level == ResultLevel.INFO else\
            ("[w]" if result.level == ResultLevel.WARNING else "[ok]")

        print(f"{prefix} {result.test_name}: {result.description}")
