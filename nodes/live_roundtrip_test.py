"""OPT-IN live round trip against a real S3-compatible store (Neon Object
Storage, or any SigV4 store such as SeaweedFS/MinIO for a local run).

Skipped unless all five env vars are set — they stand in for the five tenant
secrets and never appear in output:
  STORAGE_LIVE_ENDPOINT  STORAGE_LIVE_REGION  STORAGE_LIVE_BUCKET
  STORAGE_LIVE_ACCESS_KEY_ID  STORAGE_LIVE_SECRET_ACCESS_KEY
The bucket must already exist. Every object it writes lives under a fresh
random prefix and is deleted at the end.
"""
import os
import time
import urllib.error
import urllib.request
import uuid

import pytest

from gen.axiom_context import AxiomNodeError
from gen.messages_pb2 import (DeleteObjectInput, HeadObjectInput, PresignGetInput,
                              PresignPutInput, StorageConnection)
from nodes.delete_object import delete_object
from nodes.fakes_test import Ctx
from nodes.head_object import head_object
from nodes.presign_get import presign_get
from nodes.presign_put import presign_put

ENV = {
    "endpoint_secret_name": "STORAGE_LIVE_ENDPOINT",
    "region_secret_name": "STORAGE_LIVE_REGION",
    "bucket_secret_name": "STORAGE_LIVE_BUCKET",
    "access_key_id_secret_name": "STORAGE_LIVE_ACCESS_KEY_ID",
    "secret_access_key_secret_name": "STORAGE_LIVE_SECRET_ACCESS_KEY",
}
pytestmark = pytest.mark.skipif(
    not all(os.environ.get(v) for v in ENV.values()), reason="live storage env not set")


def _ax():
    return Ctx({v: os.environ[v] for v in ENV.values()})


def _conn():
    return StorageConnection(**ENV)


def _send(method, url, body=None, headers=None):
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def test_round_trip():
    ax, conn = _ax(), _conn()
    prefix = f"storage-tools-live/{uuid.uuid4().hex}"
    key = f"{prefix}/rö port q3.bin"
    payload = os.urandom(1024)

    assert head_object(ax, HeadObjectInput(connection=conn, key=key)).exists is False

    put = presign_put(ax, PresignPutInput(connection=conn, key=key, content_type="application/pdf",
                                          content_length=len(payload), max_bytes=10 * 1024 * 1024,
                                          expires_s=120))
    # NEGATIVES first: the signed headers are binding.
    st, _, _ = _send("PUT", put.url, payload, {"Content-Type": "image/png"})
    assert st == 403, f"wrong Content-Type accepted ({st})"
    st, _, _ = _send("PUT", put.url, payload + b"x", {"Content-Type": "application/pdf"})
    assert st in (400, 403), f"wrong length accepted ({st})"
    tampered = put.url[:-1] + ("0" if put.url[-1] != "0" else "1")
    st, _, _ = _send("PUT", tampered, payload, dict(put.headers))
    assert st == 403, f"tampered signature accepted ({st})"
    assert head_object(ax, HeadObjectInput(connection=conn, key=key)).exists is False

    st, _, _ = _send("PUT", put.url, payload, {"Content-Type": put.headers["Content-Type"]})
    assert st == 200, f"presigned PUT failed ({st})"

    head = head_object(ax, HeadObjectInput(connection=conn, key=key))
    assert (head.exists, head.size, head.content_type) == (True, 1024, "application/pdf")

    get = presign_get(ax, PresignGetInput(connection=conn, key=key, download_name="résumé.pdf"))
    st, hdrs, body = _send("GET", get.url)
    assert st == 200 and body == payload
    disp = {k.lower(): v for k, v in hdrs.items()}.get("content-disposition", "")
    assert disp.startswith("attachment;") and "filename*=UTF-8''r%C3%A9sum%C3%A9.pdf" in disp

    # A GET URL cannot be used to write.
    st, _, _ = _send("PUT", get.url, b"overwrite")
    assert st == 403

    short = presign_get(ax, PresignGetInput(connection=conn, key=key, expires_s=1))
    time.sleep(2.5)
    st, _, body = _send("GET", short.url)
    assert st == 403 and body != payload, f"expired URL still served ({st})"

    # Unsigned length: any size the store accepts.
    key2 = f"{prefix}/free.txt"
    free = presign_put(ax, PresignPutInput(connection=conn, key=key2, content_type="text/plain"))
    st, _, _ = _send("PUT", free.url, b"0123456789", {"Content-Type": "text/plain"})
    assert st == 200
    assert head_object(ax, HeadObjectInput(connection=conn, key=key2)).size == 10
    assert delete_object(ax, DeleteObjectInput(connection=conn, key=key2)).ok is True

    assert delete_object(ax, DeleteObjectInput(connection=conn, key=key)).ok is True
    assert head_object(ax, HeadObjectInput(connection=conn, key=key)).exists is False
    assert delete_object(ax, DeleteObjectInput(connection=conn, key=key)).ok is True  # idempotent
    st, _, _ = _send("GET", get.url)
    assert st == 404


def test_wrong_secret_is_forbidden():
    ax = Ctx({**{v: os.environ[v] for v in ENV.values()}, "STORAGE_LIVE_SECRET_ACCESS_KEY": "wrong-secret"})
    with pytest.raises(AxiomNodeError) as e:
        head_object(ax, HeadObjectInput(connection=_conn(), key="storage-tools-live/none"))
    assert e.value.code == "STORAGE_FORBIDDEN"
