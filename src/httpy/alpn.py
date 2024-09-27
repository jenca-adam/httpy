import ssl


def alpn_negotiate(sock, context, host):
    wrapped = context.wrap_socket(sock, server_hostname=host)
    return wrapped.selected_alpn_protocol(), wrapped
