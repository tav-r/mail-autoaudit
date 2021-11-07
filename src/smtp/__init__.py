from .scan import vrfy_available, expn_available, is_open_relay,\
    optional_starttls

from .send import send_eicar, fake_from

scan_funcs = {
    vrfy_available.__name__: vrfy_available,
    expn_available.__name__: expn_available,
    is_open_relay.__name__: is_open_relay,
    optional_starttls.__name__: optional_starttls
}

send_funcs = {
    fake_from.__name__: fake_from,
    send_eicar.__name__: send_eicar
}
