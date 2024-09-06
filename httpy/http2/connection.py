import socket
import ssl
import queue
import threading
import traceback
import sys
import asyncio
import ctypes

from ..utils import force_bytes, _create_connection_and_handle_errors, _extract_sslobj
from ..ssl_context import generate_ssl_context
from . import hpack, frame, stream, settings
from .streams import Streams
from .frame_queue import FrameQueue, AsyncFrameQueue
from .error import *
from .window import Window

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def initiate_connection(sock, client_settings):
    """
    Initiates the connection on a socket by sending the connection preface and exchanging settings frames
    """
    sf = sock.makefile("b")
    sock.sendall(PREFACE + frame.SettingsFrame(**client_settings.settings).tobytes())
    sett = frame.parse(sf).dict
    server_settings = settings.Settings(sett, {}, sett)
    sock.sendall(frame.SettingsFrame(ack=True).tobytes())
    return True, sock, server_settings


def start_connection(
    host, port, client_settings, check_hostname, cert, verify, alpn=True
):
    """
    Starts a connection to a given server.
    """
    context = generate_ssl_context(
        check_hostname=check_hostname,
        cert=cert,
        verify=verify,
        alpn_protocols=["h2"] if alpn else [],
    )
    sock = context.wrap_socket(
        _create_connection_and_handle_errors((host, port)), server_hostname=host
    )
    if sock.selected_alpn_protocol() != "h2":
        return False, sock, None
    return initiate_connection(sock, client_settings)


async def async_initiate_connection(reader, writer, client_settings):
    """
    Initiates an asynchronous connection by sending the connection preface and exchanging settings frames
    """
    writer.write(PREFACE)
    await writer.drain()
    sett = (await frame.async_parse(reader)).dict
    server_settings = settings.Settings(sett, {}, sett)
    writer.write(frame.SettingsFrame(ack=True).tobytes())
    writer.write(frame.SettingsFrame(**client_settings.settings).tobytes())
    await writer.drain()
    return True, (reader, writer), server_settings


async def async_start_connection(
    host, port, client_settings, check_hostname, cert, verify, alpn=True
):
    """
    Starts an asynchronous connection to a given server
    """
    context = generate_ssl_context(
        check_hostname=check_hostname,
        verify=verify,
        cert=cert,
        alpn_protocols=["h2"] if alpn else None,
    )
    try:
        reader, writer = await asyncio.open_connection(
            host, port, ssl=context, server_hostname=host
        )
    except socket.gaierror as gai:
        # ctrl-c ctrl-v
        debugger.warn("gaierror raised, getting errno")
        if hasattr(ctypes, "pythonapi"):
            errno = ctypes.c_int.in_dll(ctypes.pythonapi, "errno").value

        else:
            errno = -1
            if str(gai).startswith("[Errno -2]") or str(gai).startswith("[Errno -3]"):
                errno = 2
        if errno in [2, 3]:
            raise ServerError(f"could not find server {host!r}")

        debugger.warn(f"unknown errno {errno!r}")
        raise
    ssl_obj = _extract_sslobj(reader, writer)
    if ssl_obj is None:
        debugger.error("SSLObject extraction failed")
        return False, (reader, writer), None
    if ssl_obj.selected_alpn_protocol() != "h2":
        debugger.error("ALPN failed (not h2)")
        return False, (reader, writer), None
    return await async_initiate_connection(reader, writer, client_settings)


class Connection:
    """
    A synchronous HTTP/2 Conection implementation
    """

    def __init__(
        self,
        host,
        port,
        debugger,
        cert=None,
        verify=None,
        check_hostname=True,
        client_settings={},
        sock=None,
    ):
        self.debugger = debugger
        self.host = host
        self.port = port
        self.client_hpack, self.server_hpack = hpack.HPACK(), hpack.HPACK()
        self.settings = settings.Settings(client_settings, client_settings, {})
        self.streams = Streams(128, self)
        self.highest_id = -1
        self.sockfile = None
        self.sock = sock
        self.server_settings = None
        self.open = False
        self.out_queue = queue.Queue()
        self.errorqueue = queue.Queue()
        self._last_stream_id = 0x0
        self.processing_queue = FrameQueue(self.streams, self)
        self.window = None
        self.outbound_window = None
        self._processing = False
        self.from_socket = self.sock is not None

    def _after_start(fun):
        def _wrapper(self, *args, **kwargs):
            if not self.open:
                raise RuntimeError(f"Can't run {fun.__name__}: Connection closed.")
            return fun(self, *args, **kwargs)

        return _wrapper

    @classmethod
    def from_socket(
        self,
        socket,
        debugger,
        host,
        port,
        cert=None,
        verify=None,
        check_hostname=True,
        client_settings={},
    ):
        """
        Builds a `Connection` from a socket
        """
        return self(
            host,
            port,
            debugger,
            client_settings=client_settings,
            cert=cert,
            verify=verify,
            check_hostname=check_hostname,
            sock=socket,
        )

    @property
    def _sock(self):
        return self.sock

    @_after_start
    def create_stream(self):
        """
        Creates a new stream for the connection.
        """
        new_stream_id = self.highest_id + 2
        self.highest_id += 2
        s = stream.Stream(new_stream_id, self, self.settings["initial_window_size"])
        self.debugger.info(f"starting a new stream {new_stream_id}")
        self.streams.add_stream(s)
        self.processing_queue.add_stream(s)
        return s

    def start(self):
        """
        Starts a HTTP2 connection to the server.
        """
        if self.from_socket:
            self.debugger.info("Initiating h2 connection")
            success, self.sock, self.server_settings = initiate_connection(
                self.sock, self.settings
            )
        else:
            self.debugger.info("starting connection")
            success, self.sock, self.server_settings = start_connection(
                self.host, self.port, self.settings
            )
            if not success:
                self.debugger.warn("no h2 in ALPN")
                raise ConnectionError(
                    "failed to connect: server does not support http2"
                )
        self.debugger.ok("connection started successfully")
        self.open = True
        self.settings = settings.merge_settings(self.server_settings, self.settings)
        self.sockfile = self.sock.makefile("b")
        self.window = Window(self.settings["initial_window_size"])
        self.outbound_window = self.settings.server_settings["initial_window_size"]

        return True, self.sock

    def update_server_settings(self, new_settings):
        """
        Updates the server_settings upon the receival of a SETTINGS frame
        """
        new_window_size = new_settings.get("max_window_size", None)  # can't use walrus
        if new_window_size is not None:
            self.window.update_max_window_size(new_window_size)

        self.server_settings.settings.update(new_settings)
        self.settings = settings.merge_settings(new_settings, self.settings)

    def update_settings(self, **new_settings):
        """
        Sends a SETTINGS frame with new settings
        """
        self.settings = settings.merge_client_settings(new_settings, self.settings)
        self.send_frame(frame.SettingsFrame(**new_settings))

    def close(self, errcode=0x0, debug=b""):
        """
        Closes the connection by sending a GOAWAY frame
        """
        self.debugger.info("GOAWAY")
        fr = frame.GoAwayFrame(self._last_stream_id, errcode, force_bytes(debug))
        try:
            self._send_frame(fr)
        except:  # ignore ALL errors on close since these happen fairly frequently
            pass
        self.close_socket()

    @_after_start
    def close_on_error(self, err):
        """
        Closes the connection with a debug message after an error has occured.
        """
        self.debugger.error(f"{err}: closing connection")
        self.close(err.code, str(err))

    @_after_start
    def close_socket(self, quit=True):
        """
        Closes the underlying socket.
        """
        self.debugger.info("Closing socket")
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except ssl.SSLError:  # application data after close notify
            pass
        self.sock.close()
        self.sockfile.close()
        self.open = False
        self.out_queue.put(None)
        self.processing_queue.quit()

    @_after_start
    def close_on_internal_error(self, e):
        self.close_on_error(INTERNAL_ERROR(f"{e.__class__.__name__}: {str(e)}"))

    @_after_start
    def _send_frame_from_queue(self, out_queue, errq):
        try:
            next_frame = self.out_queue.get()

            if next_frame is None:
                return
            if next_frame.frame_type == frame.HTTP2_FRAME_DATA:
                self.outbound_window -= next_frame.payload_length
            self.debugger.info(f"to send: {next_frame}")
            self._send_frame(next_frame)

            ## No error?
            errq.put(0)
        except Exception as e:
            errq.put(e)

    @_after_start
    def process_next_frame(self):
        """
        Processes the next frame in queue.
        """
        if self._processing or self.sockfile.closed or (not self.open):
            return
        self._processing = True
        try:
            dt = frame.parse_data(self.sock)
            if dt is None:
                return self.process_next_frame()
            if dt == frame.ConnectionToken.CONNECTION_CLOSE:
                return
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
            to_send = (self.processing_queue.process(next_frame), window_update)
            for fr in to_send:
                if fr is not None:
                    self.debugger.info(f"Sending back: {fr}")
                    self.send_frame(fr)

        except HTTP2Error as e:
            if e.send:
                self.close_on_error(e)
            else:
                self.close_socket(False)
            self.processing_queue.throw(sys.exc_info())
        except Exception as e:
            self.close_on_internal_error(e)
            self.processing_queue.throw(sys.exc_info())
        finally:
            self._processing = False

    @_after_start
    def _send_frame(self, frame):
        self.sock.send(frame.tobytes())

    @_after_start
    def _recv_frame(self):
        q = frame.parse(self.sockfile)
        return q

    @_after_start
    def send_frame(self, frame):
        """
        Sends a frame to the server.
        """
        if frame.payload_length > self.outbound_window:
            raise Refuse("refusing to send the frame: not enough space in window")
        self.debugger.info(f"sending {frame}")
        self.out_queue.put(frame)
        self._send_frame_from_queue(self.out_queue, self.errorqueue)
        err = False
        while not self.errorqueue.empty():
            next_error = self.errorqueue.get()
            if next_error == 0:
                continue
            else:
                err = next_error
            try:
                sys.stderr.write(traceback.format_tb(next_error))
            except:
                pass
        if err:
            raise err


class AsyncConnection:
    """
    Asynchronous HTTP/2 Connection implementation.
    For method description, see Connection.__doc__
    """

    def __init__(
        self,
        host,
        port,
        debugger,
        check_hostname=True,
        cert=None,
        verify=None,
        client_settings={},
        sock=None,
    ):
        self.debugger = debugger
        self.debugger.do_debug = True
        self.processed = asyncio.Event()
        self.processed.set()
        self.host = host
        self.port = port
        self.client_hpack, self.server_hpack = hpack.HPACK(), hpack.HPACK()
        self.settings = settings.Settings(client_settings, client_settings, {})
        self.streams = Streams(128, self)
        self.highest_id = -1
        self.sockfile = None
        self.sock = sock
        self.server_settings = None
        self.open = False
        self.out_queue = asyncio.Queue()
        self.errorqueue = asyncio.Queue()
        self._last_stream_id = 0x0
        self.processing_queue = AsyncFrameQueue(self.streams, self)
        self.window = None
        self.outbound_window = None
        self.from_socket = self.sock is not None
        self.check_hostname = check_hostname
        self.cert = cert
        self.verify = verify

    def _after_start(fun):
        def _wrapper(self, *args, **kwargs):
            if not self.open:
                raise RuntimeError(f"Can't run {fun.__name__}: Connection closed.")
            return fun(self, *args, **kwargs)

        return _wrapper

    @classmethod
    def from_socket(self, socket, debugger, host, port, client_settings={}):
        return self(host, port, debugger, client_settings, socket)

    @property
    def _sock(self):
        return self.sock

    @_after_start
    def create_stream(self):
        new_stream_id = self.highest_id + 2
        self.highest_id += 2
        s = stream.AsyncStream(
            new_stream_id, self, self.settings["initial_window_size"]
        )
        self.debugger.info(f"starting a new stream {new_stream_id}")
        self.streams.add_stream(s)
        self.processing_queue.add_stream(s)
        return s

    async def start(self):
        if self.from_socket:
            self.debugger.info("Initiating h2 connection")
            success, self.sock, self.server_settings = await async_initiate_connection(
                self.sock, self.settings
            )
        else:
            self.debugger.info("starting connection")
            success, self.sock, self.server_settings = await async_start_connection(
                self.host,
                self.port,
                self.settings,
                self.check_hostname,
                self.cert,
                self.verify,
            )
            if not success:
                self.debugger.warn("no h2 in ALPN")
                raise ConnectionError(
                    "failed to connect: server does not support http2"
                )
        self.debugger.ok("connection started successfully")
        self.open = True
        self.settings = settings.merge_settings(self.server_settings, self.settings)
        self.window = Window(self.settings["initial_window_size"])
        self.outbound_window = self.settings.server_settings["initial_window_size"]

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

    async def close(self, errcode=0x0, debug=b""):
        if self.open:
            self.debugger.info("Sending GOAWAY frame")
            fr = frame.GoAwayFrame(self._last_stream_id, errcode, force_bytes(debug))
            try:
                await self._send_frame(fr)
            except:  # see above
                pass
            await self.close_socket()

    async def close_on_error(self, err):
        self.debugger.info(f"{err}: closing connection")
        await self.close(err.code, str(err))

    async def close_socket(self, quit=True):
        self.debugger.info("Closing socket")
        self.open = False
        reader, writer = self.sock
        try:
            writer.close()
            await writer.wait_closed()
        except ssl.SSLError:  # application data after close notify
            pass
        # await writer.transport.connection_lost()

        await self.out_queue.put(None)
        await self.processing_queue.quit()

    async def close_on_internal_error(self, e):
        await self.close_on_error(INTERNAL_ERROR(f"{e.__class__.__name__}: {str(e)}"))

    @_after_start
    async def _send_frame_from_queue(self, out_queue, errq):
        try:
            next_frame = await self.out_queue.get()

            if next_frame is None:
                return
            if next_frame.frame_type == frame.HTTP2_FRAME_DATA:
                self.outbound_window -= frame.payload_length
            self.debugger.info(f"to send: {next_frame}")
            await self._send_frame(next_frame)

            ## No error?
            await errq.put(0)
        except Exception as e:
            await errq.put(e)

    @_after_start
    async def process_next_frame(self, queue):
        reader, writer = self.sock
        if not self.open:
            return
        if not self.processed.is_set():
            return
        if not queue.empty():
            return
        self.processed.clear()
        try:
            dt = await frame.async_parse_data(reader)
            if dt is None:
                return await self.process_next_frame()
            if dt == frame.ConnectionToken.CONNECTION_CLOSE:
                return dt
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
            to_send = (await self.processing_queue.process(next_frame), window_update)
            for fr in to_send:
                if fr is not None:
                    self.debugger.info(f"Sending back: {fr}")
                    await self.send_frame(fr)

        except HTTP2Error as e:
            if e.send:
                await self.close_on_error(e)
            else:
                await self.close_socket(False)
            await self.processing_queue.throw(sys.exc_info())
        except Exception as e:
            await self.close_on_internal_error(e)
            await self.processing_queue.throw(sys.exc_info())
        finally:
            self.processed.set()

    @_after_start
    async def _send_frame(self, frame):
        reader, writer = self.sock
        writer.write(frame.tobytes())
        await writer.drain()

    @_after_start
    async def _recv_frame(self):
        reader, writer = self.sock
        return await frame.async_parse(reader)

    @_after_start
    async def send_frame(self, frame):
        if frame.payload_length > self.outbound_window:
            raise Refuse("refusing to send the frame: not enough space in window")
        self.debugger.info(f"sending {frame}")
        await self.out_queue.put(frame)
        await self._send_frame_from_queue(self.out_queue, self.errorqueue)
        err = False
        while not self.errorqueue.empty():
            next_error = await self.errorqueue.get()
            if next_error == 0:
                continue
            else:
                err = True
            sys.stderr.write(traceback.format_tb(next_error))
        if err:
            raise err
