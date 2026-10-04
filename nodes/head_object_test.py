"""HeadObject: one signed HEAD (botocore-identical Authorization), 404 → exists
false, 403 → STORAGE_FORBIDDEN, 5xx/transport retried then STORAGE_UNAVAILABLE."""
import pytest

from gen.axiom_context import AxiomNodeError
from gen.messages_pb2 import HeadObjectInput, HeadObjectResult
from nodes.fakes_test import NOW, Ctx, FakeConn, connection
from nodes.head_object import _head_object

HOST = "br-cool-tree-a1b2c3.storage.c-1.us-east-2.aws.neon.tech"
BOTO_HEAD_SIG = "bd152815c6ac854c6a1e27873f52658a5e8e147e832ff127eb0e0f6ae13a1608"
KEY = "acme/notes/42/7/report q3.pdf"


def run(script, key=KEY):
    fc, sleeps = FakeConn(script), []
    out = _head_object(Ctx(), HeadObjectInput(connection=connection(), key=key),
                       now_fn=lambda: NOW, sleep=sleeps.append, conn_factory=fc.factory)
    return out, fc, sleeps


def test_existing_object():
    out, fc, sleeps = run([(200, {"Content-Length": "1024", "Content-Type": "image/png", "ETag": '"x"'})])
    assert isinstance(out, HeadObjectResult)
    assert (out.exists, out.size, out.content_type) == (True, 1024, "image/png")
    assert len(fc.calls) == 1 and sleeps == []
    call = fc.calls[0]
    assert call["host"] == HOST
    assert call["method"] == "HEAD"
    assert call["uri"] == "/app-files/acme/notes/42/7/report%20q3.pdf"
    assert call["headers"]["Host"] == HOST
    assert call["headers"]["Authorization"].endswith(f"Signature={BOTO_HEAD_SIG}")
    assert fc.closed == 1


def test_missing_object_is_not_an_error():
    out, _, _ = run([(404, {})])
    assert (out.exists, out.size, out.content_type) == (False, 0, "")


def test_forbidden():
    with pytest.raises(AxiomNodeError) as e:
        run([(403, {})])
    assert e.value.code == "STORAGE_FORBIDDEN"
    assert e.value.detail == {"method": "HEAD", "status": "403"}


def test_other_client_error():
    with pytest.raises(AxiomNodeError) as e:
        run([(400, {})])
    assert e.value.code == "STORAGE_HTTP_400"


def test_retries_5xx_then_succeeds():
    out, fc, sleeps = run([(503, {}), (500, {}), (200, {"Content-Length": "7", "Content-Type": "text/plain"})])
    assert (out.exists, out.size) == (True, 7)
    assert len(fc.calls) == 3 and sleeps == [0.25, 0.5]


def test_gives_up_after_three_attempts():
    with pytest.raises(AxiomNodeError) as e:
        run([OSError("boom"), (502, {}), ConnectionResetError()])
    assert e.value.code == "STORAGE_UNAVAILABLE"
    assert e.value.detail == {"method": "HEAD", "last": "ConnectionResetError"}


def test_bad_key_never_reaches_the_network():
    fc = FakeConn([])
    with pytest.raises(AxiomNodeError) as e:
        _head_object(Ctx(), HeadObjectInput(connection=connection(), key="../x"), conn_factory=fc.factory)
    assert e.value.code == "KEY_INVALID"
    assert fc.calls == []
