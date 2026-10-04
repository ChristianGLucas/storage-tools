"""Shared core for the storage-tools nodes: SigV4 signing, path-style URLs,
input validation, secret resolution and the two signed HTTP calls.

Not a node (it is not listed in axiom.yaml) — every handler imports it.

The signer is AWS Signature Version 4 for the `s3` service, written out in
full rather than pulled from botocore: it is ~60 lines of hashing, it keeps the
image free of a 13 MB dependency, and it is pinned by the tests to AWS's own
documented presigned-URL vector plus vectors derived from botocore's presigner
(see storage_core_test.py).

Errors are AxiomNodeError with a stable code. No message or detail ever
carries a secret VALUE — only secret NAMES, which are not sensitive.
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Mapping, Optional, Tuple
from urllib.parse import quote, urlsplit

from gen.axiom_context import AxiomNodeError, SecretStatus

ALGORITHM = "AWS4-HMAC-SHA256"
SERVICE = "s3"
UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()

DEFAULT_EXPIRES_S = 600
# SigV4 presigned URLs cannot outlive seven days (X-Amz-Expires ceiling).
MAX_EXPIRES_S = 604800
# S3's object-key limit, in UTF-8 bytes.
MAX_KEY_BYTES = 1024

# The five connection slots, in the order the proto declares them.
CONNECTION_SLOTS = (
    "endpoint_secret_name",
    "region_secret_name",
    "bucket_secret_name",
    "access_key_id_secret_name",
    "secret_access_key_secret_name",
)

_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"
)


# ── SigV4 primitives ───────────────────────────────────────────────────────


def uri_encode(value: str, keep_slash: bool) -> str:
    """SigV4 URI-encoding: every byte except the unreserved set is %XX
    (uppercase hex). S3 keeps '/' literal in the path and encodes it in the
    query; it does NOT double-encode the path."""
    out = []
    for b in value.encode("utf-8"):
        c = chr(b)
        if c in _UNRESERVED or (keep_slash and c == "/"):
            out.append(c)
        else:
            out.append("%%%02X" % b)
    return "".join(out)


def canonical_query(params: Mapping[str, str]) -> str:
    pairs = sorted((uri_encode(k, False), uri_encode(v, False)) for k, v in params.items())
    return "&".join(f"{k}={v}" for k, v in pairs)


def _canonical_header_value(v: str) -> str:
    return " ".join(v.strip().split())


def canonical_headers(headers: Mapping[str, str]) -> Tuple[str, str]:
    """Returns (canonical header block, signed-headers list)."""
    norm = sorted((k.strip().lower(), _canonical_header_value(v)) for k, v in headers.items())
    block = "".join(f"{k}:{v}\n" for k, v in norm)
    signed = ";".join(k for k, _ in norm)
    return block, signed


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def signing_key(secret_access_key: str, date: str, region: str) -> bytes:
    k = _hmac(("AWS4" + secret_access_key).encode("utf-8"), date)
    k = _hmac(k, region)
    k = _hmac(k, SERVICE)
    return _hmac(k, "aws4_request")


def amz_times(now: datetime) -> Tuple[str, str]:
    now = now.astimezone(timezone.utc)
    return now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")


def signature(secret_access_key: str, region: str, now: datetime, canonical_request: str) -> str:
    amz_date, date = amz_times(now)
    scope = f"{date}/{region}/{SERVICE}/aws4_request"
    string_to_sign = "\n".join([
        ALGORITHM,
        amz_date,
        scope,
        hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
    ])
    key = signing_key(secret_access_key, date, region)
    return hmac.new(key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()


def presign_url(
    *,
    method: str,
    scheme: str,
    host: str,
    canonical_uri: str,
    region: str,
    access_key_id: str,
    secret_access_key: str,
    now: datetime,
    expires_s: int,
    headers: Optional[Mapping[str, str]] = None,
    extra_query: Optional[Mapping[str, str]] = None,
) -> str:
    """Query-string-authenticated SigV4 URL. `headers` are the headers the
    client must send verbatim besides Host (they are signed)."""
    amz_date, date = amz_times(now)
    signed_hdrs: Dict[str, str] = {"host": host}
    for k, v in (headers or {}).items():
        signed_hdrs[k.lower()] = v
    hdr_block, signed_list = canonical_headers(signed_hdrs)
    params: Dict[str, str] = dict(extra_query or {})
    params.update({
        "X-Amz-Algorithm": ALGORITHM,
        "X-Amz-Credential": f"{access_key_id}/{date}/{region}/{SERVICE}/aws4_request",
        "X-Amz-Date": amz_date,
        "X-Amz-Expires": str(expires_s),
        "X-Amz-SignedHeaders": signed_list,
    })
    cq = canonical_query(params)
    creq = "\n".join([method, canonical_uri, cq, hdr_block, signed_list, UNSIGNED_PAYLOAD])
    sig = signature(secret_access_key, region, now, creq)
    return f"{scheme}://{host}{canonical_uri}?{cq}&X-Amz-Signature={sig}"


def authorization_headers(
    *,
    method: str,
    host: str,
    canonical_uri: str,
    region: str,
    access_key_id: str,
    secret_access_key: str,
    now: datetime,
    payload_sha256: str = EMPTY_SHA256,
) -> Dict[str, str]:
    """Header-authenticated SigV4 for a bodiless request (HEAD/DELETE).
    Returns every header the request must carry, Host included."""
    amz_date, date = amz_times(now)
    hdrs = {"host": host, "x-amz-content-sha256": payload_sha256, "x-amz-date": amz_date}
    hdr_block, signed_list = canonical_headers(hdrs)
    creq = "\n".join([method, canonical_uri, "", hdr_block, signed_list, payload_sha256])
    sig = signature(secret_access_key, region, now, creq)
    return {
        "Host": host,
        "x-amz-content-sha256": payload_sha256,
        "x-amz-date": amz_date,
        "Authorization": (
            f"{ALGORITHM} Credential={access_key_id}/{date}/{region}/{SERVICE}/aws4_request, "
            f"SignedHeaders={signed_list}, Signature={sig}"
        ),
    }


# ── the store: resolved connection + validated inputs ─────────────────────


@dataclass(frozen=True)
class Store:
    scheme: str
    host: str  # netloc as the client must send it in Host (default port dropped)
    region: str
    bucket: str
    access_key_id: str
    secret_access_key: str

    def object_uri(self, key: str) -> str:
        """Path-style canonical URI: /<bucket>/<key>."""
        return "/" + uri_encode(self.bucket, False) + "/" + uri_encode(key, True)


def _resolve_secret(ax, slot: str, name: str) -> str:
    if not name.strip():
        raise AxiomNodeError(
            "SECRET_NAME_REQUIRED",
            f"connection.{slot} is empty; the binding Instance must pin a secret name there",
            {"slot": slot},
        )
    value, found = ax.secrets.get(name)
    if found and value and value.strip():
        return value.strip()
    state = "UNSET"
    try:
        st = ax.secrets.status(name)
        state = st.name if isinstance(st, SecretStatus) else str(st)
    except Exception:  # status() is advisory; the failure below stands either way
        pass
    if found and state == "AVAILABLE":
        state = "EMPTY"
    raise AxiomNodeError(
        "SECRET_UNAVAILABLE",
        f"secret {name} (connection.{slot}) is not available to this node ({state}); "
        "declare it in the Instance's required_secrets and set it (and, for dev runs, "
        "dev-arm it) in Console > Secrets",
        {"slot": slot, "secret_name": name, "state": state},
    )


def resolve_store(ax, connection) -> Store:
    vals = {slot: _resolve_secret(ax, slot, getattr(connection, slot)) for slot in CONNECTION_SLOTS}

    parts = urlsplit(vals["endpoint_secret_name"])
    if (
        parts.scheme not in ("http", "https")
        or not parts.hostname
        or parts.path not in ("", "/")
        or parts.query
        or parts.fragment
        or parts.username
        or parts.password
    ):
        raise AxiomNodeError(
            "ENDPOINT_INVALID",
            "the storage endpoint secret must be an absolute http(s) URL with no path, "
            "query or credentials (e.g. https://br-xxx.storage.c-1.us-east-2.aws.neon.tech)",
            {"slot": "endpoint_secret_name"},
        )
    host = parts.hostname.lower()
    if ":" in host:  # IPv6 literal
        host = f"[{host}]"
    port = parts.port
    if port is not None and not (
        (parts.scheme == "https" and port == 443) or (parts.scheme == "http" and port == 80)
    ):
        host = f"{host}:{port}"

    region = vals["region_secret_name"]
    if region.startswith("aws-"):
        region = region[len("aws-"):]
    if not region or any(c.isspace() or c == "/" for c in region):
        raise AxiomNodeError("REGION_INVALID", "the storage region secret is not a valid region name",
                             {"slot": "region_secret_name"})

    bucket = vals["bucket_secret_name"]
    if "/" in bucket or any(c.isspace() for c in bucket):
        raise AxiomNodeError("BUCKET_INVALID", "the storage bucket secret must be a bare bucket name",
                             {"slot": "bucket_secret_name"})

    return Store(
        scheme=parts.scheme,
        host=host,
        region=region,
        bucket=bucket,
        access_key_id=vals["access_key_id_secret_name"],
        secret_access_key=vals["secret_access_key_secret_name"],
    )


def validate_key(key: str) -> str:
    def bad(reason: str):
        raise AxiomNodeError("KEY_INVALID", f"object key {reason}", {"reason": reason})

    if not key:
        bad("is empty")
    if len(key.encode("utf-8")) > MAX_KEY_BYTES:
        bad(f"exceeds {MAX_KEY_BYTES} UTF-8 bytes")
    if key.startswith("/"):
        bad("must not start with '/'")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in key):
        bad("must not contain control characters")
    for seg in key.split("/"):
        if seg in ("", ".", ".."):
            bad("must not contain empty, '.' or '..' path segments")
    return key


def validate_expires(expires_s: int) -> int:
    if expires_s == 0:
        return DEFAULT_EXPIRES_S
    if expires_s < 0 or expires_s > MAX_EXPIRES_S:
        raise AxiomNodeError(
            "EXPIRES_INVALID",
            f"expires_s must be between 1 and {MAX_EXPIRES_S} seconds (0 means {DEFAULT_EXPIRES_S})",
            {"expires_s": str(expires_s)},
        )
    return expires_s


def validate_header_value(field: str, value: str) -> str:
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        raise AxiomNodeError(f"{field.upper()}_INVALID", f"{field} must not contain control characters",
                             {"field": field})
    return _canonical_header_value(value)


def content_disposition(download_name: str) -> str:
    """RFC 6266 attachment disposition: an ASCII-safe `filename` fallback plus
    the exact UTF-8 name in `filename*` (RFC 5987)."""
    name = download_name.strip().replace("/", "_").replace("\\", "_")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in name):
        raise AxiomNodeError("DOWNLOAD_NAME_INVALID", "download_name must not contain control characters",
                             {"field": "download_name"})
    fallback = "".join(c if 0x20 <= ord(c) < 0x7F and c not in '"%' else "_" for c in name)
    encoded = quote(name, safe="!#$&+-.^_`|~")
    return f"attachment; filename=\"{fallback}\"; filename*=UTF-8''{encoded}"


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


# ── signed HTTP for HEAD / DELETE ─────────────────────────────────────────

_ATTEMPTS = 3
_TIMEOUT_S = 15


def signed_request(store: Store, method: str, key: str, *, now_fn=now_utc, sleep=time.sleep, conn_factory=None):
    """Send one bodiless signed request; retries 5xx and transport failures
    (a node's own call is never platform-retried). Returns (status, headers)
    with header names lowercased."""
    uri = store.object_uri(key)
    factory = conn_factory or (
        http.client.HTTPSConnection if store.scheme == "https" else http.client.HTTPConnection
    )
    last = ""
    for attempt in range(_ATTEMPTS):
        if attempt:
            sleep(0.25 * (2 ** (attempt - 1)))
        headers = authorization_headers(
            method=method, host=store.host, canonical_uri=uri, region=store.region,
            access_key_id=store.access_key_id, secret_access_key=store.secret_access_key,
            now=now_fn(),
        )
        conn = factory(store.host, timeout=_TIMEOUT_S)
        try:
            conn.request(method, uri, headers=headers)
            resp = conn.getresponse()
            resp.read()
            status = resp.status
            hdrs = {k.lower(): v for k, v in resp.getheaders()}
        except (OSError, http.client.HTTPException) as exc:
            last = type(exc).__name__
            continue
        finally:
            conn.close()
        if status >= 500:
            last = f"HTTP {status}"
            continue
        return status, hdrs
    raise AxiomNodeError(
        "STORAGE_UNAVAILABLE",
        f"the storage endpoint did not answer {method} after {_ATTEMPTS} attempts ({last})",
        {"method": method, "last": last},
    )


def refuse_status(method: str, status: int):
    if status == 403:
        raise AxiomNodeError(
            "STORAGE_FORBIDDEN",
            f"the store refused {method} (403): the credential lacks the scope, is revoked, "
            "or belongs to another branch",
            {"method": method, "status": "403"},
        )
    raise AxiomNodeError(
        f"STORAGE_HTTP_{status}",
        f"the store answered {method} with HTTP {status}",
        {"method": method, "status": str(status)},
    )
