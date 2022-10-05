from .scan import vrfy_available, expn_available, is_open_relay,\
    optional_starttls

from .send import send_eicar, send_zipped_eicar, fake_from_header,\
    mail_from_invalid_domain, mail_from_yourself, ehlo_invalid_domain

scan_funcs = {
    vrfy_available.__name__: vrfy_available,
    expn_available.__name__: expn_available,
    is_open_relay.__name__: is_open_relay,
    optional_starttls.__name__: optional_starttls
}

send_funcs = {
    fake_from_header.__name__: fake_from_header,
    mail_from_invalid_domain.__name__: mail_from_invalid_domain,
    mail_from_yourself.__name__: mail_from_yourself,
    ehlo_invalid_domain.__name__: ehlo_invalid_domain,
    "send_eicar": send_eicar,
    "send_zipped_eicar": send_zipped_eicar,
    "send_gtube": send_gtube
}
