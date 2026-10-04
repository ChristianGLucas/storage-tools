from gen.messages_pb2 import PresignPutInput, PresignPutResult
from gen.axiom_context import AxiomContext, AxiomNodeError
from nodes import storage_core as core


def presign_put(ax: AxiomContext, input: PresignPutInput) -> PresignPutResult:
    """Mint a short-lived SigV4 presigned PUT URL that lets a browser upload one
    object straight to the bucket without holding a credential. Pure signing:
    no network call, nothing stored, safe to repeat. Content-Type and (when
    content_length > 0) Content-Length are signed, so the upload must send
    them exactly as returned in `headers`; max_bytes caps content_length."""
    return _presign_put(ax, input, core.now_utc())


def _presign_put(ax, input: PresignPutInput, now) -> PresignPutResult:
    key = core.validate_key(input.key)
    expires = core.validate_expires(input.expires_s)
    if input.content_length < 0:
        raise AxiomNodeError("CONTENT_LENGTH_INVALID", "content_length must be >= 0 (0 means unsigned)",
                             {"content_length": str(input.content_length)})
    if input.max_bytes < 0:
        raise AxiomNodeError("MAX_BYTES_INVALID", "max_bytes must be >= 0 (0 means no cap)",
                             {"max_bytes": str(input.max_bytes)})
    if input.max_bytes > 0:
        # A presigned PUT can only pin an exact length, so a cap is enforceable
        # only through a declared one — refuse rather than mint an uncapped URL.
        if input.content_length == 0:
            raise AxiomNodeError(
                "MAX_BYTES_REQUIRES_CONTENT_LENGTH",
                "max_bytes can only be enforced on a presigned PUT through an exact content_length; "
                "pass the upload's size as content_length",
                {"max_bytes": str(input.max_bytes)})
        if input.content_length > input.max_bytes:
            raise AxiomNodeError(
                "MAX_BYTES_EXCEEDED", "content_length exceeds max_bytes",
                {"content_length": str(input.content_length), "max_bytes": str(input.max_bytes)})
    signed = {}
    if input.content_type.strip():
        signed["Content-Type"] = core.validate_content_type(input.content_type)
    if input.content_length > 0:
        signed["Content-Length"] = str(input.content_length)
    store = core.resolve_store(ax, input.connection)
    url = core.presign_url(
        method="PUT", scheme=store.scheme, host=store.host, canonical_uri=store.object_uri(key),
        region=store.region, access_key_id=store.access_key_id,
        secret_access_key=store.secret_access_key, now=now, expires_s=expires, headers=signed,
    )
    out = PresignPutResult(url=url, method="PUT", expires_at_unix=int(now.timestamp()) + expires)
    out.headers.update(signed)
    return out
