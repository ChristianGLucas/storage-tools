"""Signer + validation tests for the shared core.

Two independent oracles pin the signer:
  * AWS's own documented SigV4 examples (S3 API reference, "Signature
    Calculations for the Authorization Header" and "Authenticating Requests:
    Using Query Parameters") — fixed credential AKIAIOSFODNN7EXAMPLE, fixed
    time 20130524T000000Z, signatures copied verbatim from the docs.
  * botocore's presigner/S3SigV4Auth, path-style, clock frozen — derived by
    scripts/derive_botocore_vectors.py and pinned here.
"""
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit

import pytest

from gen.axiom_context import AxiomNodeError
from nodes import storage_core as core
from nodes.fakes_test import AKID, BUCKET, ENDPOINT, NOW, SECRET, Ctx, NAMES, VALUES, connection

AWS_AKID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_NOW = datetime(2013, 5, 24, 0, 0, 0, tzinfo=timezone.utc)

# botocore-derived vectors (scripts/derive_botocore_vectors.py).
BOTO_HEAD_SIG = "bd152815c6ac854c6a1e27873f52658a5e8e147e832ff127eb0e0f6ae13a1608"
BOTO_DELETE_SIG = "dc765e94323f50353490e0dcaddc0a9e8df7ce15cb87b956cd56563587a10b8f"


# ── AWS documented vectors ────────────────────────────────────────────────


def test_aws_documented_presigned_get_vector():
    url = core.presign_url(
        method="GET", scheme="https", host="examplebucket.s3.amazonaws.com",
        canonical_uri="/test.txt", region="us-east-1", access_key_id=AWS_AKID,
        secret_access_key=AWS_SECRET, now=AWS_NOW, expires_s=86400,
    )
    assert url == (
        "https://examplebucket.s3.amazonaws.com/test.txt"
        "?X-Amz-Algorithm=AWS4-HMAC-SHA256"
        "&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request"
        "&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host"
        "&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
    )


def test_aws_documented_header_auth_get_object_vector():
    block, signed = core.canonical_headers({
        "Host": "examplebucket.s3.amazonaws.com",
        "Range": "bytes=0-9",
        "x-amz-content-sha256": core.EMPTY_SHA256,
        "x-amz-date": "20130524T000000Z",
    })
    assert signed == "host;range;x-amz-content-sha256;x-amz-date"
    creq = "\n".join(["GET", "/test.txt", "", block, signed, core.EMPTY_SHA256])
    assert core.signature(AWS_SECRET, "us-east-1", AWS_NOW, creq) == (
        "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")


def test_aws_documented_signing_key_derivation():
    # The "deriving the signing key" example from the SigV4 docs (service iam).
    import hmac, hashlib
    k = core._hmac(("AWS4" + "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY").encode(), "20120215")
    k = core._hmac(k, "us-east-1")
    k = core._hmac(k, "iam")
    k = core._hmac(k, "aws4_request")
    assert k.hex() == "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"


# ── botocore cross-check: header auth for HEAD / DELETE ───────────────────


@pytest.mark.parametrize("method,sig", [("HEAD", BOTO_HEAD_SIG), ("DELETE", BOTO_DELETE_SIG)])
def test_header_auth_matches_botocore(method, sig):
    store = core.resolve_store(Ctx(), connection())
    hdrs = core.authorization_headers(
        method=method, host=store.host, canonical_uri=store.object_uri("acme/notes/42/7/report q3.pdf"),
        region=store.region, access_key_id=store.access_key_id,
        secret_access_key=store.secret_access_key, now=NOW,
    )
    assert hdrs["Authorization"] == (
        f"AWS4-HMAC-SHA256 Credential={AKID}/20261004/us-east-2/s3/aws4_request, "
        f"SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={sig}")
    assert hdrs["x-amz-date"] == "20261004T123045Z"
    assert hdrs["x-amz-content-sha256"] == core.EMPTY_SHA256
    assert hdrs["Host"] == "br-cool-tree-a1b2c3.storage.c-1.us-east-2.aws.neon.tech"


# ── encoding ──────────────────────────────────────────────────────────────


def test_uri_encode():
    assert core.uri_encode("a b/c~d.e_f-g", True) == "a%20b/c~d.e_f-g"
    assert core.uri_encode("a b/c", False) == "a%20b%2Fc"
    assert core.uri_encode("café+&=?#%", True) == "caf%C3%A9%2B%26%3D%3F%23%25"
    assert core.uri_encode("日本", True) == "%E6%97%A5%E6%9C%AC"


def test_canonical_query_sorts_by_encoded_key():
    assert core.canonical_query({"b": "2", "a": "x y", "A": "/"}) == "A=%2F&a=x%20y&b=2"


def test_canonical_headers_trim_and_collapse():
    block, signed = core.canonical_headers({"Content-Type": "  text/plain;   charset=utf-8 ", "HOST": "h"})
    assert block == "content-type:text/plain; charset=utf-8\nhost:h\n"
    assert signed == "content-type;host"


# ── key validation ────────────────────────────────────────────────────────


@pytest.mark.parametrize("key", [
    "a", "acme/notes/42/7/report q3.pdf", "x/ünïcødé/文件.txt", "a..b/c...d", "k" * 1024,
    "é" * 512,  # 1024 UTF-8 bytes exactly
])
def test_valid_keys(key):
    assert core.validate_key(key) == key


@pytest.mark.parametrize("key,reason", [
    ("", "is empty"),
    ("/abs", "must not start with '/'"),
    ("a/../b", "path segments"),
    ("..", "path segments"),
    ("a/./b", "path segments"),
    ("a//b", "path segments"),
    ("a/", "path segments"),
    ("a\nb", "control characters"),
    ("a\x00b", "control characters"),
    ("a\x7fb", "control characters"),
    ("k" * 1025, "exceeds 1024"),
    ("é" * 513, "exceeds 1024"),
])
def test_invalid_keys(key, reason):
    with pytest.raises(AxiomNodeError) as e:
        core.validate_key(key)
    assert e.value.code == "KEY_INVALID"
    assert reason in e.value.message


@pytest.mark.parametrize("given,want", [(0, 600), (1, 1), (600, 600), (604800, 604800)])
def test_expires_accepted(given, want):
    assert core.validate_expires(given) == want


@pytest.mark.parametrize("given", [-1, 604801, 2**31 - 1])
def test_expires_refused(given):
    with pytest.raises(AxiomNodeError) as e:
        core.validate_expires(given)
    assert e.value.code == "EXPIRES_INVALID"


def test_content_disposition():
    assert core.content_disposition("résumé.txt") == (
        "attachment; filename=\"r_sum_.txt\"; filename*=UTF-8''r%C3%A9sum%C3%A9.txt")
    assert core.content_disposition('my "q" 100%.pdf') == (
        "attachment; filename=\"my _q_ 100_.pdf\"; filename*=UTF-8''my%20%22q%22%20100%25.pdf")
    assert core.content_disposition("../etc/passwd") == (
        "attachment; filename=\".._etc_passwd\"; filename*=UTF-8''.._etc_passwd")
    with pytest.raises(AxiomNodeError) as e:
        core.content_disposition("a\r\nSet-Cookie: x")
    assert e.value.code == "DOWNLOAD_NAME_INVALID"


# ── connection resolution ─────────────────────────────────────────────────


def test_resolve_store_reads_exactly_the_five_named_secrets():
    ax = Ctx()
    store = core.resolve_store(ax, connection())
    assert ax.secrets.asked == [NAMES[s] for s in core.CONNECTION_SLOTS]
    assert store == core.Store(
        scheme="https", host="br-cool-tree-a1b2c3.storage.c-1.us-east-2.aws.neon.tech",
        region="us-east-2", bucket=BUCKET, access_key_id=AKID, secret_access_key=SECRET)
    assert store.object_uri("a b/c.txt") == "/app-files/a%20b/c.txt"


@pytest.mark.parametrize("endpoint,scheme,host", [
    ("https://S3.Example.com/", "https", "s3.example.com"),
    ("https://s3.example.com:443", "https", "s3.example.com"),
    ("https://s3.example.com:8443", "https", "s3.example.com:8443"),
    ("http://127.0.0.1:9000", "http", "127.0.0.1:9000"),
    ("http://minio:80", "http", "minio"),
    ("  https://s3.example.com  ", "https", "s3.example.com"),
])
def test_endpoint_forms(endpoint, scheme, host):
    store = core.resolve_store(Ctx({**VALUES, NAMES["endpoint_secret_name"]: endpoint}), connection())
    assert (store.scheme, store.host) == (scheme, host)


@pytest.mark.parametrize("endpoint", [
    "s3.example.com", "ftp://s3.example.com", "https://s3.example.com/bucket",
    "https://s3.example.com?x=1", "https://user:pw@s3.example.com", "https://?q",
])
def test_endpoint_refused_without_echoing_it(endpoint):
    with pytest.raises(AxiomNodeError) as e:
        core.resolve_store(Ctx({**VALUES, NAMES["endpoint_secret_name"]: endpoint}), connection())
    assert e.value.code == "ENDPOINT_INVALID"
    assert endpoint not in str(e.value) and endpoint not in str(e.value.detail)


def test_region_aws_prefix_is_stripped():
    store = core.resolve_store(Ctx({**VALUES, NAMES["region_secret_name"]: "aws-eu-central-1"}), connection())
    assert store.region == "eu-central-1"


@pytest.mark.parametrize("slot,value,code", [
    ("region_secret_name", "us east", "REGION_INVALID"),
    ("region_secret_name", "aws-", "REGION_INVALID"),
    ("bucket_secret_name", "a/b", "BUCKET_INVALID"),
    ("bucket_secret_name", "a b", "BUCKET_INVALID"),
])
def test_bad_region_or_bucket(slot, value, code):
    with pytest.raises(AxiomNodeError) as e:
        core.resolve_store(Ctx({**VALUES, NAMES[slot]: value}), connection())
    assert e.value.code == code
    assert e.value.detail["slot"] == slot


@pytest.mark.parametrize("slot", core.CONNECTION_SLOTS)
def test_empty_secret_name_slot(slot):
    with pytest.raises(AxiomNodeError) as e:
        core.resolve_store(Ctx(), connection(**{slot: ""}))
    assert e.value.code == "SECRET_NAME_REQUIRED"
    assert e.value.detail == {"slot": slot}


@pytest.mark.parametrize("slot", core.CONNECTION_SLOTS)
def test_unset_secret(slot):
    secrets = dict(VALUES)
    del secrets[NAMES[slot]]
    with pytest.raises(AxiomNodeError) as e:
        core.resolve_store(Ctx(secrets), connection())
    assert e.value.code == "SECRET_UNAVAILABLE"
    assert e.value.detail == {"slot": slot, "secret_name": NAMES[slot], "state": "UNSET"}


def test_revoked_and_empty_secrets_are_told_apart():
    name = NAMES["secret_access_key_secret_name"]
    secrets = {k: v for k, v in VALUES.items() if k != name}
    with pytest.raises(AxiomNodeError) as e:
        core.resolve_store(Ctx(secrets, revoked={name}), connection())
    assert e.value.detail["state"] == "REVOKED"
    with pytest.raises(AxiomNodeError) as e:
        core.resolve_store(Ctx({**VALUES, name: "   "}), connection())
    assert e.value.detail["state"] == "EMPTY"


def test_no_error_ever_carries_a_secret_value():
    # Every failure path that runs after the secrets are read.
    cases = [
        ({**VALUES, NAMES["endpoint_secret_name"]: "ftp://" + SECRET}, "ENDPOINT_INVALID"),
        ({**VALUES, NAMES["bucket_secret_name"]: SECRET + "/x"}, "BUCKET_INVALID"),
        ({**VALUES, NAMES["region_secret_name"]: SECRET + " x"}, "REGION_INVALID"),
    ]
    for secrets, code in cases:
        with pytest.raises(AxiomNodeError) as e:
            core.resolve_store(Ctx(secrets), connection())
        assert e.value.code == code
        blob = str(e.value) + repr(e.value.detail)
        assert SECRET not in blob and AKID not in blob
