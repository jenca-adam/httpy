import ssl


def generate_ssl_context(
    check_hostname=True, cert=None, verify=None, alpn_protocols=None
):
    ctx = ssl.create_default_context()
    ctx.check_hostname = check_hostname
    if cert is not None:
        ctx.load_cert_chain(*cert)
    if verify is not None:
        ctx.load_verify_locations(verify)
    if alpn_protocols is not None:
        ctx.set_alpn_protocols(alpn_protocols)
    return ctx
