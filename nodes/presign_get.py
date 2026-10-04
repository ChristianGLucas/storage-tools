from gen.messages_pb2 import PresignGetInput, PresignGetResult
from gen.axiom_context import AxiomContext
from nodes import storage_core as core


def presign_get(ax: AxiomContext, input: PresignGetInput) -> PresignGetResult:
    """Mint a short-lived SigV4 presigned GET URL that downloads one object with a
    plain browser request. Pure signing: no network call, nothing stored, safe to
    repeat. With download_name set, the store answers with
    Content-Disposition: attachment and that file name."""
    return _presign_get(ax, input, core.now_utc())


def _presign_get(ax, input: PresignGetInput, now) -> PresignGetResult:
    key = core.validate_key(input.key)
    expires = core.validate_expires(input.expires_s)
    extra = {}
    if input.download_name.strip():
        extra["response-content-disposition"] = core.content_disposition(input.download_name)
    store = core.resolve_store(ax, input.connection)
    url = core.presign_url(
        method="GET", scheme=store.scheme, host=store.host, canonical_uri=store.object_uri(key),
        region=store.region, access_key_id=store.access_key_id,
        secret_access_key=store.secret_access_key, now=now, expires_s=expires, extra_query=extra,
    )
    return PresignGetResult(url=url, expires_at_unix=int(now.timestamp()) + expires)
