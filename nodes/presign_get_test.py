"""PresignGet: botocore-identical presigned GET, with and without a signed
response-content-disposition."""
from urllib.parse import parse_qs, urlsplit

import pytest

from gen.axiom_context import AxiomNodeError
from gen.messages_pb2 import PresignGetInput, PresignGetResult
from nodes.fakes_test import AKID, NOW, Ctx, connection
from nodes.presign_get import _presign_get

HOST = "br-cool-tree-a1b2c3.storage.c-1.us-east-2.aws.neon.tech"
BOTO_GET_PLAIN_SIG = "525cac2c98c2346a54bba36340fce140ebcb8130a4a78d9eba6c3401f6dfec0a"
BOTO_GET_DISPOSITION_SIG = "cf7fdc8190bbb0e3ce83cda79244dd28bd0b101584318e030915db883a013cc3"


def _q(url):
    return {k: v[0] for k, v in parse_qs(urlsplit(url).query, keep_blank_values=True).items()}


def test_plain_get_matches_botocore():
    out = _presign_get(Ctx(), PresignGetInput(connection=connection(), key="acme/notes/42/7/report q3.pdf"), NOW)
    assert isinstance(out, PresignGetResult)
    parts = urlsplit(out.url)
    assert (parts.scheme, parts.netloc, parts.path) == ("https", HOST, "/app-files/acme/notes/42/7/report%20q3.pdf")
    assert _q(out.url) == {
        "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
        "X-Amz-Credential": f"{AKID}/20261004/us-east-2/s3/aws4_request",
        "X-Amz-Date": "20261004T123045Z",
        "X-Amz-Expires": "600",
        "X-Amz-SignedHeaders": "host",
        "X-Amz-Signature": BOTO_GET_PLAIN_SIG,
    }
    assert out.expires_at_unix == int(NOW.timestamp()) + 600


def test_download_name_signs_a_utf8_attachment_disposition_like_botocore():
    out = _presign_get(Ctx(), PresignGetInput(
        connection=connection(), key="a/b/c.txt", expires_s=3600, download_name="résumé.txt"), NOW)
    q = _q(out.url)
    assert q["response-content-disposition"] == (
        "attachment; filename=\"r_sum_.txt\"; filename*=UTF-8''r%C3%A9sum%C3%A9.txt")
    assert q["X-Amz-Signature"] == BOTO_GET_DISPOSITION_SIG
    assert q["X-Amz-Expires"] == "3600"
    assert out.expires_at_unix == int(NOW.timestamp()) + 3600


def test_blank_download_name_adds_no_disposition():
    out = _presign_get(Ctx(), PresignGetInput(connection=connection(), key="k", download_name="   "), NOW)
    assert "response-content-disposition" not in _q(out.url)


@pytest.mark.parametrize("inp,code", [
    (dict(key=""), "KEY_INVALID"),
    (dict(key="a//b"), "KEY_INVALID"),
    (dict(key="k", expires_s=-1), "EXPIRES_INVALID"),
    (dict(key="k", download_name="x\ny"), "DOWNLOAD_NAME_INVALID"),
])
def test_refusals(inp, code):
    ax = Ctx()
    with pytest.raises(AxiomNodeError) as e:
        _presign_get(ax, PresignGetInput(connection=connection(), **inp), NOW)
    assert e.value.code == code
    assert ax.secrets.asked == []
