import json

from smtp import scan_funcs, send_funcs
from dns import dns_checks
from argparse import ArgumentParser, Namespace


def catch_wrapper(f, *args, **kwargs):
    try:
        return f(*args, **kwargs)
    except Exception as e:
        return f"Error: {e}"


def dns_audit(args: Namespace):
    domain = args.domain

    print(json.dumps(
        {
            n: catch_wrapper(f, domain) for n, f in dns_checks.items()
        },
        indent=4
    ))

def smtp_scan(args: Namespace):
    print(json.dumps(
        {
            n: f(
                args.host,
                args.port,
                args.sender_host
            ) for n, f in scan_funcs.items()
        },
        indent=4
    ))


def send_mails(args):
    for n, f in send_funcs.items():
        f(args.host, args.port, args.recipient, args.sender_host)


def main():
    ap = ArgumentParser()

    sub_parsers = ap.add_subparsers(
        help="sub-commands help"
    )

    # configure 'dns' subcommand
    dns_parser = sub_parsers.add_parser(
        "dns", help="check mail-specific DNS config"
    )
    dns_parser.set_defaults(func=dns_audit)
    dns_parser.add_argument("domain")

    # configure 'smtp' subcommand
    smtp_parser = sub_parsers.add_parser(
        "smtp", help="scan SMTP server for security issues"
    )
    smtp_parser.set_defaults(func=smtp_scan)
    smtp_parser.add_argument(
        "-t", "--host", dest="host", help="mail server address", required=True
    )
    smtp_parser.add_argument(
        "-p", "--port", dest="port", help="SMTP server port", default=25,
        type=int, required=False
    )
    smtp_parser.add_argument(
        "-s", "--sender-host", dest="sender_host",
        help="hostname of the sending server", required=True
    )

    # configure "send" subcommand
    send_parser = sub_parsers.add_parser(
        "send", help="send various test emails"
    )
    send_parser.set_defaults(func=send_mails)
    send_parser.add_argument(
        "-t", "--host", dest="host", help="mail server address", required=True
    )
    send_parser.add_argument(
        "-p", "--port", dest="port", help="SMTP server port", default=25,
        type=int, required=False
    )
    send_parser.add_argument(
        "-s", "--sender-host", dest="sender_host",
        help="hostname of the sending server", required=True
    )
    send_parser.add_argument(
        "-r", "--recipient", dest="recipient",
        help="mail address of the recipient", required=True
    )

    args = ap.parse_args()

    args.func(args)


if __name__ == "__main__":
    main()
