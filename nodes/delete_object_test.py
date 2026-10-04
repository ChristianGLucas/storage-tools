"""DeleteObject: one signed DELETE (botocore-identical Authorization); 204/200
and 404 are ok (idempotent), 403 is STORAGE_FORBIDDEN."""
import pytest

from gen.axiom_context import AxiomNodeError
from gen.messages_pb2 import DeleteObjectInput, DeleteObjectResult
from nodes.fakes_test import NOW, Ctx, FakeConn, connection
from nodes.delete_object import _delete_object

BOTO_DELETE_SIG = "dc765e94323f50353490e0dcaddc0a9e8df7ce15cb87b956cd56563587a10b8f"
KEY = "acme/notes/42/7/report q3.pdf"


def run(script):
    fc = FakeConn(script)
    out = _delete_object(Ctx(), DeleteObjectInput(connection=connection(), key=KEY),
                         now_fn=lambda: NOW, sleep=lambda s: None, conn_factory=fc.factory)
    return out, fc


@pytest.mark.parametrize("status", [204, 200, 404])
def test_gone_is_ok(status):
    out, fc = run([(status, {})])
    assert isinstance(out, DeleteObjectResult)
    assert out.ok is True
    call = fc.calls[0]
    assert call["method"] == "DELETE"
    assert call["uri"] == "/app-files/acme/notes/42/7/report%20q3.pdf"
    assert call["headers"]["Authorization"].endswith(f"Signature={BOTO_DELETE_SIG}")


def test_forbidden():
    with pytest.raises(AxiomNodeError) as e:
        run([(403, {})])
    assert e.value.code == "STORAGE_FORBIDDEN"
    assert e.value.detail["method"] == "DELETE"


def test_conflict_is_a_typed_error_not_ok():
    with pytest.raises(AxiomNodeError) as e:
        run([(409, {})])
    assert e.value.code == "STORAGE_HTTP_409"


def test_retry_then_ok():
    out, fc = run([(500, {}), (204, {})])
    assert out.ok is True and len(fc.calls) == 2
