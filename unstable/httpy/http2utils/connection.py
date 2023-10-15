import socket
import ssl
import frame
import settings
import stream
import hpack
import queue
import threading
import traceback
import sys
from streams import Streams
from frame_queue import FrameQueue
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
    sock.settimeout(10)
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
        self.open = False
        self.out_queue = queue.Queue()
        self.sending_thread = None
        self.receiving_thread = None
        self.errorqueue = queue.Queue()
        self.processing_queue = FrameQueue(self.streams, self)

    def _after_start(fun):
        def _wrapper(self, *args, **kwargs):
            if not self.open:
                raise RuntimeError(f"Can't run {fun.__name__}: Connection closed.")
            return fun(self, *args, **kwargs)

        return _wrapper

    @_after_start
    def close(self, errcode=0x0, debugdata=b""):
        self.send_frame(frame.GoAwayFrame(errcode, debugdata))

    @_after_start
    def create_stream(self):
        new_stream_id = self.highest_id + 2
        self.highest_id += 2
        s = stream.Stream(new_stream_id, self)
        self.streams.add_stream(s)
        self.processing_queue.add_stream(s)
        return s

    def start(self):
        success, self.socket, self.server_settings = start_connection(
            self.host, self.port, self.settings
        )
        if not success:
            raise ConnectionError("failed to connect: server does not support http2")
        self.open = True
        self.settings = settings.merge_settings(self.server_settings, self.settings)
        self.sockfile = self.socket.makefile("b")
        self.run_loops()
        return True, self.socket

    def run_loops(self):
        self.sending_thread = threading.Thread(
            target=self._sending_loop, args=(self.errorqueue,)
        )
        self.receiving_thread = threading.Thread(
            target=self._receiving_loop, args=(self.errorqueue,)
        )
        self.sending_thread.start()
        self.receiving_thread.start()

    @_after_start
    def _sending_loop(self, errq):
        while True:
            try:
                next_frame = self.out_queue.get()
                print("send", next_frame)
                self._send_frame(next_frame)

                ## No error?
                errq.put(0)
            except Exception as e:
                errq.put(e)

    @_after_start
    def _receiving_loop(self, errq):
        while True:
            try:
                next_frame = frame.parse(self.sockfile)
                print("recv", next_frame)
                to_send = self.processing_queue.process(next_frame)
                if to_send:
                    self.send_frame(to_send)
                ## No error?
                errq.put(0)
            except Exception as e:
                errq.put(e)

    @_after_start
    def _send_frame(self, frame):
        self.socket.send(frame.tobytes())

    @_after_start
    def _recv_frame(self):
        return frame.parse(self.sockfile)
        while not self.errorqueue.empty():
            next_error = self.errorqueue.get()
            if next_error == 0:
                continue
            sys.stderr.write(traceback.format_tb(next_error))

    @_after_start
    def send_frame(self, frame):
        self.out_queue.put(frame)
        while not self.errorqueue.empty():
            next_error = self.errorqueue.get()
            if next_error == 0:
                continue
            sys.stderr.write(traceback.format_tb(next_error))
