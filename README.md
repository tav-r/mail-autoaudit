# Mail auto test
## Usage
Checkout help parameters:
```bash
$ ./autoaudit -h
usage: audit_cli.py [-h] {dns,smtp,send,check_setup} ...

positional arguments:
  {dns,smtp,send,check_setup}
                        sub-commands help
    dns                 check mail-specific DNS config
    smtp                scan SMTP server for security issues
    send                send various test emails
    check_setup         get info about your own IP (useful to check your setup)

optional arguments:
  -h, --help            show this help message and exit
$ /autoaudit dns -h
usage: audit_cli.py dns [-h] domain

positional arguments:
  domain

optional arguments:
  -h, --help  show this help message and exit
$ ./autoaudit smtp -h
usage: audit_cli.py smtp [-h] -t HOST [-p PORT] -s SENDER_ADDR

optional arguments:
  -h, --help            show this help message and exit
  -t HOST, --host HOST  mail server address
  -p PORT, --port PORT  SMTP server port
  -s SENDER_ADDR, --sender-address SENDER_ADDR
                        email address used to send mails
$ ./autoaudit send -h
usage: audit_cli.py send [-h] -t HOST [-p PORT] -s SENDER_ADDR -r RECIPIENT

optional arguments:
  -h, --help            show this help message and exit
  -t HOST, --host HOST  mail server address
  -p PORT, --port PORT  SMTP server port
  -s SENDER_ADDR, --sender-address SENDER_ADDR
                        email address used to send mails
  -r RECIPIENT, --recipient RECIPIENT
                        mail address of the recipient
$ ./autoaudit check_setup -h
usage: audit_cli.py check_setup [-h] -s SENDER_ADDR

optional arguments:
  -h, --help            show this help message and exit
  -s SENDER_ADDR, --sender-address SENDER_ADDR
                        email address used to send mails
```

### Examples
Checking DNS config of "nmap.com":
```bash
$ ./autoaudit dns nmap.com
{
    "ipv4_reverse_match": {
        "ALT1.ASPMX.L.GOOGLE.com.": {
            "142.250.153.26": [
                "ea-in-f26.1e100.net."
            ]
        },
        "ALT2.ASPMX.L.GOOGLE.com.": {
            "142.251.9.26": [
                "rc-in-f26.1e100.net."
            ]
        },
        "ASPMX.L.GOOGLE.com.": {
            "173.194.76.27": [
                "ws-in-f27.1e100.net."
            ]
        },
        "ASPMX2.GOOGLEMAIL.com.": {
            "142.250.153.27": [
                "ea-in-f27.1e100.net."
            ]
        },
        "ASPMX3.GOOGLEMAIL.com.": {
            "142.251.9.27": [
                "rc-in-f27.1e100.net."
            ]
        }
    },
    "ipv6_reverse_match": {
        "ALT1.ASPMX.L.GOOGLE.com.": {
            "2a00:1450:4013:c16::1b": [
                "ea-in-f27.1e100.net."
            ]
        },
        "ALT2.ASPMX.L.GOOGLE.com.": {
            "2a00:1450:4025:c03::1a": [
                "rc-in-f26.1e100.net."
            ]
        },
        "ASPMX.L.GOOGLE.com.": {
            "2a00:1450:400c:c08::1b": [
                "wq-in-x1b.1e100.net.",
                "wq-in-f27.1e100.net."
            ]
        },
        "ASPMX2.GOOGLEMAIL.com.": {
            "2a00:1450:4013:c16::1a": [
                "ea-in-f26.1e100.net."
            ]
        },
        "ASPMX3.GOOGLEMAIL.com.": {
            "2a00:1450:4025:c03::1b": [
                "rc-in-f27.1e100.net."
            ]
        }
    },
    "dmarc_record": "Error: Could not resolve domain '_dmarc.nmap.com'",
    "mx_record": [
        "5 ALT1.ASPMX.L.GOOGLE.com.",
        "10 ASPMX3.GOOGLEMAIL.com.",
        "5 ALT2.ASPMX.L.GOOGLE.com.",
        "10 ASPMX2.GOOGLEMAIL.com.",
        "1 ASPMX.L.GOOGLE.com."
    ],
    "spf_record": [
        "45.33.49.119",
        "2600:3c01:e000:3e6::6d4e:7061",
        {
            "sender.zohobooks.com": [
                {
                    "transmail.net": [
                        "136.143.188.0/24",
                        "135.84.80.0/24",
                        "135.84.82.0/24",
                        "117.20.43.11/32",
                        "136.143.184.0/24"
                    ]
                }
            ]
        },
        {
            "_spf.google.com": [
                {
                    "_netblocks.google.com": [
                        "35.190.247.0/24",
                        "64.233.160.0/19",
                        "66.102.0.0/20",
                        "66.249.80.0/20",
                        "72.14.192.0/18",
                        "74.125.0.0/16",
                        "108.177.8.0/21",
                        "173.194.0.0/16",
                        "209.85.128.0/17",
                        "216.58.192.0/19",
                        "216.239.32.0/19"
                    ]
                },
                {
                    "_netblocks2.google.com": [
                        "2001:4860:4000::/36",
                        "2404:6800:4000::/36",
                        "2607:f8b0:4000::/36",
                        "2800:3f0:4000::/36",
                        "2a00:1450:4000::/36",
                        "2c0f:fb50:4000::/36"
                    ]
                },
                {
                    "_netblocks3.google.com": [
                        "172.217.0.0/19",
                        "172.217.32.0/20",
                        "172.217.128.0/19",
                        "172.217.160.0/20",
                        "172.217.192.0/19",
                        "172.253.56.0/21",
                        "172.253.112.0/20",
                        "108.177.96.0/19",
                        "35.191.0.0/16",
                        "130.211.0.0/22"
                    ]
                }
            ]
        }
    ]
}
```
Scanning a mailservere:
```bash
$ ./autoaudit smtp -t mail.anything.anywhere -p 25 -s test@test.com
{
    "vrfy_available": false,
    "expn_available": false,
    "is_open_relay": false,
    "optional_starttls": true
}
```

## Current state
### E-Mail tests
1. "From:" different from "MAIL FROM:" ✅
2. VRFY available ✅
3. EXPN available ✅
4. Open relay ✅
5. STARTLS optional (downgrade attack) ✅
6. Malware
    - EICAR test ✅
    - Zipped EICAR test ✅
    - PE file
    - Excel with macro
    - Word with macro
7. Server fingerprinting
8. List available commands
9. Banner grabbing
10. Check NTLM auth
11. Username enumeration, with wordlist (VRFY, EXPN or RCPT TO)
12. Message size
13. Invalid domain in "MAIL FROM:" and "From:" header ✅
14. Spoof mail to look like it came from the recipient itself ✅
15. Invalid domain in EHLO, "MAIL FROM:" and "From:" header ✅

## DNS tests
1. Get relevant records
    - SPF ✅
    - DKIM
    - DMARC ✅
2. walk SPF records ✅
    - check registration domain entries (possible takover)
3. mail server reverse ip ✅
4. get mailservers (MX) ✅
5. get mailaddresses from ✅
    - DNS SOA ✅
    - DMARC ✅
6. Get subdomains and check for MX records
