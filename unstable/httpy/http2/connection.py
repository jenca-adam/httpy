import socket
import ssl
import queue
import threading
import traceback
import sys
import inspect
from httpy.utils import force_bytes
from . import hpack, frame, stream, settings
from .streams import Streams
from .frame_queue import FrameQueue
from .error import *
from .window import Window

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
    sett = frame.parse(sf).dict
    server_settings = settings.Settings(sett, {}, sett)
    sock.send(frame.SettingsFrame(ack=True).tobytes())
    sock.send(frame.SettingsFrame(**client_settings.settings).tobytes())
    return True, sock, server_settings


class Connection:
    def __init__(self, host, port, debugger, client_settings={}):
        self.debugger = debugger
        self.host = host
        self.port = port
        self.client_hpack, self.server_hpack = hpack.HPACK(), hpack.HPACK()
        self.settings = settings.Settings(client_settings, client_settings, {})
        self.streams = Streams(128, self)
        self.highest_id = -1
        self.sockfile = None
        self.sock = None
        self.server_settings = None
        self.open = False
        self.out_queue = queue.Queue()
        self.sending_thread = None
        self.receiving_thread = None
        self.errorqueue = queue.Queue()
        self._last_stream_id = 0x0
        self.processing_queue = FrameQueue(self.streams, self)
        self.window = None
        self.outbound_window = None

    def _after_start(fun):
        def _wrapper(self, *args, **kwargs):
            if not self.open:
                raise RuntimeError(f"Can't run {fun.__name__}: Connection closed.")
            return fun(self, *args, **kwargs)

        return _wrapper
    @property
    def _sock(self):
        return self.sock
    def __del__(self):
        if self.open:
            self.close()

    @_after_start
    def create_stream(self):
        new_stream_id = self.highest_id + 2
        self.highest_id += 2
        s = stream.Stream(new_stream_id, self, self.settings["initial_window_size"])
        self.debugger.info(f"starting a new stream {new_stream_id}")
        self.streams.add_stream(s)
        self.processing_queue.add_stream(s)
        return s

    def start(self):
        self.debugger.info("starting connection")
        success, self.sock, self.server_settings = start_connection(
            self.host, self.port, self.settings
        )
        if not success:
            self.debugger.warn("no h2 in ALPN")
            raise ConnectionError("failed to connect: server does not support http2")
        self.debugger.ok("connection started successfully")
        self.open = True
        self.settings = settings.merge_settings(self.server_settings, self.settings)
        self.sockfile = self.sock.makefile("b")
        self.window = Window(self.settings["initial_window_size"])
        self.outbound_window = self.settings.server_settings["initial_window_size"]
        self.run_loops()

        return True, self.sock

    def update_server_settings(self, new_settings):
        new_window_size = new_settings.get("max_window_size", None)  # can't use walrus
        if new_window_size is not None:
            self.window.update_max_window_size(new_window_size)

        self.server_settings.settings.update(new_settings)
        self.settings = settings.merge_settings(new_settings, self.settings)

    def update_settings(self, **new_settings):
        self.settings = settings.merge_client_settings(new_settings, self.settings)
        self.send_frame(frame.SettingsFrame(**new_settings))

    @_after_start
    def close(self, errcode=0x0, debug=b""):
        self.debugger.info("Sending GOAWAY frame")
        fr = frame.GoAwayFrame(self._last_stream_id, errcode, force_bytes(debug))
        self._send_frame(fr)
        self.close_socket(errcode == 0x0)

    @_after_start
    def close_on_error(self, err):
        self.debugger.error(f"{err}: closing connection")
        self.close(err.code, str(err))

    @_after_start
    def close_socket(self, quit=True):
        self.debugger.info("Closing socket")
        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()
        self.sockfile.close()
        self.open = False
        self.out_queue.put(None)
        if quit:
            self.processing_queue.quit()

    @_after_start
    def close_on_internal_error(self, e):
        self.close_on_error(INTERNAL_ERROR(f"{e.__class__.__name__}: {str(e)}"))

    def run_loops(self):
        self.debugger.info("running loops")
        self.sending_thread = threading.Thread(
            target=self._sending_loop,
            args=(
                self.out_queue,
                self.errorqueue,
            ),
        )
        self.receiving_thread = threading.Thread(
            target=self._receiving_loop,
            args=(self.processing_queue, self.out_queue),
        )
        self.sending_thread.start()
        self.receiving_thread.start()

    @_after_start
    def _sending_loop(self, out_queue, errq):
        while True:
            try:
                next_frame = self.out_queue.get()
                self.debugger.info(f"to send: {next_frame}")
                if next_frame is None:
                    break
                if next_frame.frame_type == frame.HTTP2_FRAME_DATA:
                    self.outbound_window -= frame.payload_length
                self._send_frame(next_frame)

                ## No error?
                errq.put(0)
            except Exception as e:
                errq.put(e)

    @_after_start
    def _receiving_loop(self, processing_queue, out_queue):
        while True:
            if self.sockfile.closed or (not self.open):
                break
            try:
                dt = frame.parse_data(self.sockfile)
                if dt is None:
                    continue
                if dt == frame.ConnectionToken.CONNECTION_CLOSE:
                    break
                *next_frame_data, frame_type = dt
                self._last_stream_id = next_frame_data[2]

                if frame_type == frame.HTTP2_FRAME_DATA:
                    self.debugger.info("Received a data frame, updating window")
                    self.window.received_frame(next_frame_data[1])
                    window_increment = self.window.process(next_frame_data[1])
                    window_update = (
                        None
                        if window_increment == 0
                        else frame.WindowUpdateFrame(window_increment, streamid=0x0)
                    )
                else:
                    window_update = None
                next_frame = frame._parse(next_frame_data + [frame_type])
                self.debugger.info(f"Received: {next_frame}")
                to_send = (processing_queue.process(next_frame), window_update)
                for fr in to_send:
                    if fr is not None:
                        self.debugger.info(f"Sending back: {fr}")
                        out_queue.put(fr)

            except HTTP2Error as e:
                if e.send:
                    self.close_on_error(e)
                else:
                    self.close_socket(False)
                self.processing_queue.throw(sys.exc_info())
            except Exception as e:
                self.close_on_internal_error(e)
                self.processing_queue.throw(sys.exc_info())

    @_after_start
    def _send_frame(self, frame):
        self.sock.send(frame.tobytes())

    @_after_start
    def _recv_frame(self):
        q = frame.parse(self.sockfile)
        return q

    @_after_start
    def send_frame(self, frame):
        print(frame.payload)
        if frame.payload_length > self.outbound_window:
            raise Refuse("refusing to send the frame: not enough space in window")
        self.debugger.info(f"sending {frame}")
        self.out_queue.put(frame)
        err = False
        while not self.errorqueue.empty():
            next_error = self.errorqueue.get()
            if next_error == 0:
                continue
            else:
                err = True
            sys.stderr.write(traceback.format_tb(next_error))
        if err:
            raise err
