import json

from smtp import scan_funcs, send_funcs
from dns import dns_checks
from dns.spf import spf_record
from dns.helpers import reverse_lookup_ipv4, reverse_lookup_ipv6
from tcp_ip.helpers import my_ip, is_ipv4, is_ipv6
from argparse import ArgumentParser, Namespace


def catch_wrapper(f, *args, **kwargs):
    try:
        return f(*args, **kwargs)
    except Exception as e:
        return f"Error: {e}"


def dns_audit(args: Namespace):
    return (
        {
            n: catch_wrapper(f, args.domain)
            for n, f in dns_checks.items()
        }
    )


def smtp_scan(args: Namespace):
    return {
        n: f(
            args.host,
            args.port,
            args.sender_host
        ) for n, f in scan_funcs.items()
    }


def send_mails(args):
    for n, f in send_funcs.items():
        f(args.host, args.port, args.recipient, args.sender_host)


def check_setup(args):
    ip = my_ip()
    if is_ipv4(ip):
        reverse_lookup = catch_wrapper(reverse_lookup_ipv4, ip)
    elif is_ipv6(ip):
        reverse_lookup = catch_wrapper(reverse_lookup_ipv6, ip)

    return {
        "your_ip": ip,
        "reverse_lookup": reverse_lookup,
        args.domain: {
            "spf": catch_wrapper(spf_record, args.domain)
        } if args.domain else dict()
    }


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

    # configure 'check_setup' subcommand
    check_setup_parser = sub_parsers.add_parser(
        "check_setup",
        help="get info about your own IP (useful to check your setup)"
    )
    check_setup_parser.set_defaults(func=check_setup)
    check_setup_parser.add_argument(
        "-d", "--domain", dest="domain",
        help="the domain you want to use for testing", required=False
    )

    args = ap.parse_args()

    print(json.dumps(
        args.func(args), indent=4
    ))


if __name__ == "__main__":
    main()
