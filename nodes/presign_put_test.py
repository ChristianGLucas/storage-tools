"""PresignPut: the URL it mints is byte-for-byte botocore's presigned PUT (signature
and every signed query parameter), path-style off the five resolved secrets."""
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlsplit

import pytest

from gen.axiom_context import AxiomNodeError
from gen.messages_pb2 import PresignPutInput, PresignPutResult
from nodes.fakes_test import AKID, NOW, SECRET, Ctx, NAMES, VALUES, connection
from nodes.presign_put import _presign_put, presign_put

HOST = "br-cool-tree-a1b2c3.storage.c-1.us-east-2.aws.neon.tech"
# botocore generate_presigned_url('put_object', ...) — scripts/derive_botocore_vectors.py
BOTO_PUT_PLAIN_SIG = "4490bd25adcfd74d05a92a553ac4799dd53375416ad23b1c0e478871444f55d6"
BOTO_PUT_TYPED_SIZED_SIG = "c6acfc8f8c91b8c057fd90e17d8e52554502e26b74a8fe8f768cff7b966ac676"


def _q(url):
    return {k: v[0] for k, v in parse_qs(urlsplit(url).query, keep_blank_values=True).items()}


def test_plain_put_matches_botocore():
    out = _presign_put(Ctx(), PresignPutInput(connection=connection(), key="acme/notes/42/7/report q3.pdf"), NOW)
    assert isinstance(out, PresignPutResult)
    parts = urlsplit(out.url)
    assert (parts.scheme, parts.netloc, parts.path) == ("https", HOST, "/app-files/acme/notes/42/7/report%20q3.pdf")
    assert _q(out.url) == {
        "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
        "X-Amz-Credential": f"{AKID}/20261004/us-east-2/s3/aws4_request",
        "X-Amz-Date": "20261004T123045Z",
        "X-Amz-Expires": "600",  # expires_s=0 → default
        "X-Amz-SignedHeaders": "host",
        "X-Amz-Signature": BOTO_PUT_PLAIN_SIG,
    }
    assert out.method == "PUT"
    assert dict(out.headers) == {}
    assert out.expires_at_unix == int(NOW.timestamp()) + 600


def test_typed_sized_put_matches_botocore_and_returns_the_signed_headers():
    out = _presign_put(Ctx(), PresignPutInput(
        connection=connection(), key="acme/photos/9/1/café.png", content_type="image/png",
        expires_s=900, content_length=1024, max_bytes=10 * 1024 * 1024), NOW)
    assert urlsplit(out.url).path == "/app-files/acme/photos/9/1/caf%C3%A9.png"
    q = _q(out.url)
    assert q["X-Amz-SignedHeaders"] == "content-length;content-type;host"
    assert q["X-Amz-Expires"] == "900"
    assert q["X-Amz-Signature"] == BOTO_PUT_TYPED_SIZED_SIG
    assert dict(out.headers) == {"Content-Type": "image/png", "Content-Length": "1024"}
    assert out.expires_at_unix == int(NOW.timestamp()) + 900


def test_max_bytes_caps_the_declared_length_inclusive():
    at_cap = _presign_put(Ctx(), PresignPutInput(
        connection=connection(), key="k", content_length=1024, max_bytes=1024), NOW)
    assert dict(at_cap.headers) == {"Content-Length": "1024"}
    with pytest.raises(AxiomNodeError) as e:
        _presign_put(Ctx(), PresignPutInput(connection=connection(), key="k", content_length=1025, max_bytes=1024), NOW)
    assert e.value.code == "MAX_BYTES_EXCEEDED"
    assert e.value.detail == {"content_length": "1025", "max_bytes": "1024"}


def test_max_bytes_without_a_declared_length_is_refused_not_silently_uncapped():
    ax = Ctx()
    with pytest.raises(AxiomNodeError) as e:
        _presign_put(ax, PresignPutInput(connection=connection(), key="k", max_bytes=1024), NOW)
    assert e.value.code == "MAX_BYTES_REQUIRES_CONTENT_LENGTH"
    assert ax.secrets.asked == []


def test_content_length_without_cap_is_signed():
    out = _presign_put(Ctx(), PresignPutInput(connection=connection(), key="k", content_length=7), NOW)
    assert _q(out.url)["X-Amz-SignedHeaders"] == "content-length;host"
    assert dict(out.headers) == {"Content-Length": "7"}


def test_content_type_is_canonicalised_as_signed():
    out = _presign_put(Ctx(), PresignPutInput(
        connection=connection(), key="k", content_type="  text/plain;\t charset=utf-8 "), NOW)
    assert dict(out.headers) == {"Content-Type": "text/plain; charset=utf-8"}


def test_content_type_alone_is_signed_without_length():
    out = _presign_put(Ctx(), PresignPutInput(connection=connection(), key="k", content_type="text/plain"), NOW)
    assert _q(out.url)["X-Amz-SignedHeaders"] == "content-type;host"
    assert dict(out.headers) == {"Content-Type": "text/plain"}


def test_url_never_contains_the_secret_access_key():
    out = _presign_put(Ctx(), PresignPutInput(connection=connection(), key="k"), NOW)
    assert SECRET not in out.url
    from urllib.parse import quote
    assert quote(SECRET, safe="") not in out.url


def test_different_keys_and_times_sign_differently():
    a = _presign_put(Ctx(), PresignPutInput(connection=connection(), key="a/1"), NOW)
    b = _presign_put(Ctx(), PresignPutInput(connection=connection(), key="a/2"), NOW)
    c = _presign_put(Ctx(), PresignPutInput(connection=connection(), key="a/1"), NOW + timedelta(seconds=1))
    sigs = {_q(x.url)["X-Amz-Signature"] for x in (a, b, c)}
    assert len(sigs) == 3


def test_public_entry_uses_the_wall_clock():
    before = int(datetime.now(timezone.utc).timestamp())
    out = presign_put(Ctx(), PresignPutInput(connection=connection(), key="k", expires_s=60))
    after = int(datetime.now(timezone.utc).timestamp())
    assert before + 60 <= out.expires_at_unix <= after + 60
    stamp = datetime.strptime(_q(out.url)["X-Amz-Date"], "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    assert before - 1 <= int(stamp.timestamp()) <= after


@pytest.mark.parametrize("inp,code", [
    (dict(key="/abs"), "KEY_INVALID"),
    (dict(key="a/../b"), "KEY_INVALID"),
    (dict(key="k", expires_s=-5), "EXPIRES_INVALID"),
    (dict(key="k", expires_s=604801), "EXPIRES_INVALID"),
    (dict(key="k", max_bytes=-1), "MAX_BYTES_INVALID"),
    (dict(key="k", content_length=-1), "CONTENT_LENGTH_INVALID"),
    (dict(key="k", content_type="image/pngé"), "CONTENT_TYPE_INVALID"),
    (dict(key="k", content_type="text/plain\u00a0x"), "CONTENT_TYPE_INVALID"),
    (dict(key="k", content_type="text/plain\r\nX-Evil: 1"), "CONTENT_TYPE_INVALID"),
])
def test_refusals(inp, code):
    ax = Ctx()
    with pytest.raises(AxiomNodeError) as e:
        _presign_put(ax, PresignPutInput(connection=connection(), **inp), NOW)
    assert e.value.code == code
    # Input is validated before any secret is read.
    assert ax.secrets.asked == []


def test_missing_secret_is_a_typed_refusal():
    secrets = {k: v for k, v in VALUES.items() if k != NAMES["bucket_secret_name"]}
    with pytest.raises(AxiomNodeError) as e:
        _presign_put(Ctx(secrets), PresignPutInput(connection=connection(), key="k"), NOW)
    assert e.value.code == "SECRET_UNAVAILABLE"
    assert e.value.detail["secret_name"] == NAMES["bucket_secret_name"]
