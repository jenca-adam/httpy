import socket
import ssl
import frame
import settings
import stream
import hpack
import queue
import threading
from error import *

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def start_connection(host, port, client_settings, alpn=True):
    context = ssl.create_default_context()
    if alpn:
        context.set_alpn_protocols(["h2"])
    sock = context.wrap_socket(
        socket.create_connection((host, port)), server_hostname=host
    )
    if sock.selected_alpn_protocol() != "h2":
        return False, sock, None
    sf = sock.makefile("b")
    sock.send(PREFACE)
    server_settings = settings.Settings(frame.parse(sf).dict)
    sock.send(frame.SettingsFrame(ack=True).tobytes())
    sock.send(frame.SettingsFrame(**client_settings.settings).tobytes())
    return True, sock, server_settings


class Connection:
    def __init__(self, host, port, client_settings={}):
        self.host = host
        self.port = port
        self.hpack = hpack.HPACK()
        self.settings = settings.Settings(client_settings)
        self.streams = Streams(128, self)
        self.highest_id = -1
        self.sockfile = None
        self.socket = None
        self.server_settings = None
        self.started = False
        self.out_queue = queue.Queue()

    def _after_start(fun):
        def wrapper(self, *args, **kwargs):
            if not self.started:
                raise RuntimeError(
                    f"Can't run {fun.__name__} before the connection has started"
                )
            return fun(self, *args, **kwargs)

        return wrapper

    @_after_start
    def create_stream(self):
        new_stream_id = self.highest_id + 2
        self.highest_id += 2
        s = stream.Stream(new_stream_id, self)
        self.streams.add_stream(s)
        return s

    def start(self):
        success, self.socket, self.server_settings = start_connection(
            self.host, self.port, self.settings
        )
        if not success:
            return False, self.socket
        self.started = True
        self.settings = settings.merge_settings(self.server_settings, self.settings)
        self.sockfile = self.socket.makefile("b")
        return True, self.socket

    @_after_start
    def send_frame(self, frame):
        self.socket.send(frame.tobytes())

    @_after_start
    def recv_frame(self):
        return frame.parse(self.sockfile)
