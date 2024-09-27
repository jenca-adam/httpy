import pathlib

HTTPY_DIR = pathlib.Path.home() / ".cache" / "httpy"
VERSION = "2.1.2"

HTTPY_CACHEABLE_METHODS = ["GET", "HEAD"]
WEBSOCKET_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
WEBSOCKET_CONTINUATION_FRAME = 0x0
WEBSOCKET_TEXT_FRAME = 0x1
WEBSOCKET_BINARY_FRAME = 0x2
WEBSOCKET_CONNECTION_CLOSE = 0x8
WEBSOCKET_PING = 0x9
WEBSOCKET_PONG = 0xA
WEBSOCKET_OPCODES = {0x0, 0x1, 0x2, 0x8, 0x9, 0xA}
WEBSOCKET_CLOSE_CODES = {
    1000: "Normal closure",
    1001: "Going away",
    1002: "Protocol error",
    1003: "Unsupported Data",
    1005: "No status received",
    1006: "Abnormal closure",
    1007: "Invalid frame payload data",
    1008: "Policy Violation",
    1009: "Message Too Big",
    1010: "Mandatory Ext.",
    1011: "Internal Error",
    1012: "Service restart",
    1014: "Bad Gateway",
    1015: "TLS handshake",
}

ALPN_PROTOCOLS = {"1.1": ["http/1.1"], "2": ["h2"], "*": ["http/1.1", "h2"]}
