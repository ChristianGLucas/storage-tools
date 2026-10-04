from gen.messages_pb2 import DeleteObjectInput, DeleteObjectResult
from gen.axiom_context import AxiomContext
from nodes import storage_core as core


def delete_object(ax: AxiomContext, input: DeleteObjectInput) -> DeleteObjectResult:
    """Delete one object with a signed DELETE request. Deleting a key that does
    not exist also succeeds (S3 semantics), so a redelivered delete is
    harmless. A refused credential is STORAGE_FORBIDDEN."""
    return _delete_object(ax, input)


def _delete_object(ax, input: DeleteObjectInput, **http_opts) -> DeleteObjectResult:
    key = core.validate_key(input.key)
    store = core.resolve_store(ax, input.connection)
    status, _ = core.signed_request(store, "DELETE", key, **http_opts)
    if 200 <= status < 300 or status == 404:
        return DeleteObjectResult(ok=True)
    core.refuse_status("DELETE", status)
