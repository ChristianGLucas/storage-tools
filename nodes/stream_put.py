import hashlib
import http.client
from typing import Iterator
from urllib.parse import urlsplit

from gen.axiom_context import AxiomContext, AxiomNodeError
from gen.messages_pb2 import StreamPutInput, StreamPutResult
from nodes import storage_core as core

_TIMEOUT_S = 60


def stream_put(ax: AxiomContext, inputs: Iterator[StreamPutInput]) -> Iterator[StreamPutResult]:
    """Carry a file streamed in frame by frame to the presigned PUT URL its first
    frame names, as the bytes arrive, hashing them on the way; answer one frame.
    The URL (minted by PresignPut after the app's own access check) pins the key,
    type and exact length; this node only refuses a URL outside its connection's
    endpoint and bucket and a stream whose bytes do not add up to `size`."""
    yield _stream_put(ax, inputs)


def _fail(code: str, msg: str, sent: int = 0, digest: str = "") -> StreamPutResult:
    return StreamPutResult(ok=False, error_code=code, error=msg, bytes=sent, sha256=digest)


def _drain(inputs) -> None:
    for _ in inputs:
        pass


def _stream_put(ax, inputs, conn_factory=None) -> StreamPutResult:
    inputs = iter(inputs)
    first = next(inputs, None)
    if first is None:
        return _fail("NO_INPUT", "no frames: stream the file's bytes in, one frame per chunk")
    try:
        store = core.resolve_store(ax, first.connection)
    except AxiomNodeError as exc:
        _drain(inputs)
        return _fail(exc.code, exc.message)
    url = urlsplit(first.upload_url or "")
    prefix = "/" + core.uri_encode(store.bucket, False) + "/"
    if url.scheme != store.scheme or url.netloc != store.host or not url.path.startswith(prefix) \
            or "X-Amz-Signature=" not in (url.query or ""):
        _drain(inputs)
        return _fail("URL_INVALID", "upload_url is not a presigned PUT URL into this connection's bucket "
                                    "(mint it with PresignPut)")
    if first.size <= 0:
        _drain(inputs)
        return _fail("SIZE_MISMATCH", "size must be the file's exact size in bytes (> 0)")

    factory = conn_factory or (http.client.HTTPSConnection if url.scheme == "https" else http.client.HTTPConnection)
    conn = factory(store.host, timeout=_TIMEOUT_S)
    h = hashlib.sha256()
    sent = 0
    try:
        conn.putrequest("PUT", url.path + "?" + url.query, skip_accept_encoding=True)
        if first.content_type:
            conn.putheader("Content-Type", first.content_type)
        conn.putheader("Content-Length", str(first.size))
        conn.endheaders()
        frame = first
        while frame is not None:
            chunk = bytes(frame.data)
            if sent + len(chunk) > first.size:
                _drain(inputs)
                return _fail("SIZE_MISMATCH", f"the stream carried more than size ({first.size}) bytes",
                             sent, h.hexdigest())
            if chunk:
                conn.send(chunk)
                h.update(chunk)
                sent += len(chunk)
            frame = next(inputs, None)
        if sent != first.size:
            return _fail("SIZE_MISMATCH", f"the stream ended after {sent} of {first.size} bytes", sent, h.hexdigest())
        resp = conn.getresponse()
        resp.read()
        status = resp.status
    except (OSError, http.client.HTTPException) as exc:
        _drain(inputs)
        return _fail("STORAGE_UNAVAILABLE", f"the store did not take the upload ({type(exc).__name__})",
                     sent, h.hexdigest())
    finally:
        conn.close()
    if 200 <= status < 300:
        return StreamPutResult(ok=True, bytes=sent, sha256=h.hexdigest())
    code = "STORAGE_FORBIDDEN" if status == 403 else f"STORAGE_HTTP_{status}"
    return _fail(code, f"the store answered the upload with HTTP {status} (an expired or altered URL is 403)",
                 sent, h.hexdigest())
