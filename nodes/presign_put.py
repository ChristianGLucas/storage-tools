from gen.messages_pb2 import PresignPutInput, PresignPutResult
from gen.axiom_context import AxiomContext, AxiomNodeError
from nodes import storage_core as core


def presign_put(ax: AxiomContext, input: PresignPutInput) -> PresignPutResult:
    """Mint a short-lived SigV4 presigned PUT URL that lets a browser upload one
    object straight to the bucket without holding a credential. Pure signing:
    no network call, nothing stored, safe to repeat. Content-Type and (when
    max_bytes > 0) Content-Length are signed, so the upload must send them
    exactly as returned in `headers`."""
    return _presign_put(ax, input, core.now_utc())


def _presign_put(ax, input: PresignPutInput, now) -> PresignPutResult:
    key = core.validate_key(input.key)
    expires = core.validate_expires(input.expires_s)
    if input.max_bytes < 0:
        raise AxiomNodeError("MAX_BYTES_INVALID", "max_bytes must be >= 0 (0 means unbounded)",
                             {"max_bytes": str(input.max_bytes)})
    signed = {}
    if input.content_type.strip():
        signed["Content-Type"] = core.validate_header_value("content_type", input.content_type)
    if input.max_bytes > 0:
        signed["Content-Length"] = str(input.max_bytes)
    store = core.resolve_store(ax, input.connection)
    url = core.presign_url(
        method="PUT", scheme=store.scheme, host=store.host, canonical_uri=store.object_uri(key),
        region=store.region, access_key_id=store.access_key_id,
        secret_access_key=store.secret_access_key, now=now, expires_s=expires, headers=signed,
    )
    out = PresignPutResult(url=url, method="PUT", expires_at_unix=int(now.timestamp()) + expires)
    out.headers.update(signed)
    return out
