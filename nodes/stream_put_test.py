"""StreamPut: a file streamed in frame by frame reaches the presigned PUT URL byte for
byte, in order, with the signed Content-Type and Content-Length, and one answer frame
says what was sent. Bug classes: bytes dropped, doubled or reordered across frames; a
URL outside the connection's bucket accepted (the node as an open relay); a stream
shorter or longer than the signed size sent anyway; a store refusal reported as ok;
the hash or byte count wrong; the whole file buffered before sending."""
import hashlib
import http.server
import os
import threading

from gen.messages_pb2 import StreamPutInput, StreamPutResult
from nodes.fakes_test import Ctx, NAMES, VALUES, connection
from nodes.presign_put import _presign_put
from nodes.fakes_test import NOW
from gen.messages_pb2 import PresignPutInput
from nodes.stream_put import _stream_put, stream_put

HOST = "br-cool-tree-a1b2c3.storage.c-1.us-east-2.aws.neon.tech"


class StreamConn:
    """A scripted http.client connection that records the streamed request."""

    def __init__(self, status=200, fail_send_at=None):
        self.status, self.fail_send_at = status, fail_send_at
        self.host = self.method = self.target = None
        self.headers, self.sent, self.closed, self.sends = {}, b"", 0, 0

    def factory(self, host, timeout):
        self.host = host
        return self

    def putrequest(self, method, target, **kw):
        self.method, self.target = method, target

    def putheader(self, k, v):
        self.headers[k] = v

    def endheaders(self):
        pass

    def send(self, b):
        self.sends += 1
        if self.fail_send_at is not None and self.sends >= self.fail_send_at:
            raise ConnectionResetError("reset")
        self.sent += b

    def getresponse(self):
        conn = self

        class R:
            status = conn.status

            def read(self):
                return b""
        return R()

    def close(self):
        self.closed += 1


def presigned(key="acme/up/t1", size=0, content_type="audio/mpeg"):
    out = _presign_put(Ctx(), PresignPutInput(connection=connection(), key=key, content_type=content_type,
                                              content_length=size), NOW)
    return out.url


def frames(data: bytes, chunk: int, url: str, size=None, content_type="audio/mpeg"):
    out = []
    for i in range(0, max(len(data), 1), chunk):
        part = data[i:i + chunk]
        f = StreamPutInput(data=part, last=i + chunk >= len(data))
        if i == 0:
            f.connection.CopyFrom(connection())
            f.upload_url, f.content_type, f.size = url, content_type, len(data) if size is None else size
        out.append(f)
    return out


def test_bytes_arrive_in_order_with_the_signed_headers_and_one_answer():
    data = os.urandom(3 * 1024 * 1024 + 17)
    url = presigned(size=len(data))
    conn = StreamConn()
    out = _stream_put(Ctx(), frames(data, 1 << 20, url), conn_factory=conn.factory)
    assert isinstance(out, StreamPutResult)
    assert (out.ok, out.error_code, out.bytes, out.sha256) == (True, "", len(data), hashlib.sha256(data).hexdigest())
    assert conn.sent == data and conn.sends == 4          # one send per frame: streamed, not buffered
    assert conn.host == HOST and conn.method == "PUT"
    assert conn.target == url.split(HOST, 1)[1]
    assert conn.headers == {"Content-Type": "audio/mpeg", "Content-Length": str(len(data))}
    assert conn.closed == 1


def test_the_public_handler_answers_exactly_one_frame():
    data = b"hello"
    conn_frames = list(stream_put(Ctx(), iter(frames(data, 2, "https://elsewhere.example/x?X-Amz-Signature=a"))))
    assert len(conn_frames) == 1 and conn_frames[0].error_code == "URL_INVALID"


def test_a_url_outside_the_connections_bucket_is_refused_before_any_byte_moves():
    data = b"x" * 10
    good = presigned(size=10)
    for bad in (
        good.replace(HOST, "evil.example.com"),                       # another host
        good.replace("/app-files/", "/other-bucket/"),                 # another bucket
        good.split("?")[0],                                            # not presigned
        good.replace("https://", "http://"),                           # another scheme
    ):
        conn = StreamConn()
        out = _stream_put(Ctx(), frames(data, 4, bad), conn_factory=conn.factory)
        assert (out.ok, out.error_code) == (False, "URL_INVALID"), bad
        assert conn.method is None and conn.sent == b""


def test_a_stream_that_does_not_add_up_to_size_is_refused():
    data = os.urandom(100)
    short = StreamConn()
    out = _stream_put(Ctx(), frames(data, 30, presigned(size=120), size=120), conn_factory=short.factory)
    assert (out.ok, out.error_code, out.bytes) == (False, "SIZE_MISMATCH", 100)
    long = StreamConn()
    out = _stream_put(Ctx(), frames(data, 30, presigned(size=50), size=50), conn_factory=long.factory)
    assert (out.ok, out.error_code) == (False, "SIZE_MISMATCH")
    assert len(long.sent) <= 50                                  # never more than signed


def test_a_store_refusal_and_a_dropped_connection_are_not_ok():
    data = os.urandom(64)
    out = _stream_put(Ctx(), frames(data, 16, presigned(size=64)), conn_factory=StreamConn(status=403).factory)
    assert (out.ok, out.error_code, out.bytes) == (False, "STORAGE_FORBIDDEN", 64)
    out = _stream_put(Ctx(), frames(data, 16, presigned(size=64)), conn_factory=StreamConn(fail_send_at=2).factory)
    assert (out.ok, out.error_code) == (False, "STORAGE_UNAVAILABLE")


def test_an_unset_storage_secret_is_an_answer_not_a_crash():
    secrets = dict(VALUES)
    del secrets[NAMES["bucket_secret_name"]]
    out = _stream_put(Ctx(secrets=secrets), frames(b"abc", 3, presigned(size=3)))
    assert out.ok is False and out.error_code == "SECRET_UNAVAILABLE"


def test_against_a_real_socket_the_server_receives_every_byte():
    got = {}

    class H(http.server.BaseHTTPRequestHandler):
        def do_PUT(self):
            n = int(self.headers["Content-Length"])
            got["body"] = self.rfile.read(n)
            got["type"] = self.headers["Content-Type"]
            self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        endpoint = f"http://127.0.0.1:{srv.server_port}"
        secrets = {**VALUES, NAMES["endpoint_secret_name"]: endpoint}
        ctx = Ctx(secrets=secrets)
        data = os.urandom(2 * 1024 * 1024 + 3)
        url = _presign_put(ctx, PresignPutInput(connection=connection(), key="acme/up/t2", content_type="video/mp4",
                                                content_length=len(data)), NOW).url
        out = _stream_put(ctx, frames(data, 1 << 20, url, content_type="video/mp4"))
        assert out.ok, out.error
        assert got["body"] == data and got["type"] == "video/mp4"
        assert out.sha256 == hashlib.sha256(data).hexdigest()
    finally:
        srv.shutdown()
