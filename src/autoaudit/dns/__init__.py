from .helpers import dmarc_record, mx_record, soa
from .spf import spf_record
from .checks import check_ipv4_reverse_match, check_ipv6_reverse_match


dns_checks = {
    "ipv4_reverse_match": check_ipv4_reverse_match,
    "ipv6_reverse_match": check_ipv6_reverse_match,
    soa.__name__: soa,
    dmarc_record.__name__: dmarc_record,
    mx_record.__name__: mx_record,
    spf_record.__name__: spf_record
}
