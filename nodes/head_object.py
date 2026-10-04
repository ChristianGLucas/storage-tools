from gen.messages_pb2 import HeadObjectInput, HeadObjectResult
from gen.axiom_context import AxiomContext
from nodes import storage_core as core


def head_object(ax: AxiomContext, input: HeadObjectInput) -> HeadObjectResult:
    """Read one object's existence, size and Content-Type with a signed HEAD
    request. A missing object is exists=false, not an error; a refused
    credential is STORAGE_FORBIDDEN. Read-only and safe to repeat."""
    return _head_object(ax, input)


def _head_object(ax, input: HeadObjectInput, **http_opts) -> HeadObjectResult:
    key = core.validate_key(input.key)
    store = core.resolve_store(ax, input.connection)
    status, headers = core.signed_request(store, "HEAD", key, **http_opts)
    if status == 404:
        return HeadObjectResult(exists=False)
    if 200 <= status < 300:
        try:
            size = int(headers.get("content-length", "0"))
        except ValueError:
            size = 0
        return HeadObjectResult(exists=True, size=size, content_type=headers.get("content-type", ""))
    core.refuse_status("HEAD", status)
