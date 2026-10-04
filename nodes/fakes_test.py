"""Test doubles shared by the node tests (stripped from the deploy build with
every other *_test.py). Not a test module: it defines no tests."""
from datetime import datetime, timezone

from gen.axiom_context import SecretStatus
from gen.messages_pb2 import StorageConnection

NOW = datetime(2026, 10, 4, 12, 30, 45, tzinfo=timezone.utc)
ENDPOINT = "https://br-cool-tree-a1b2c3.storage.c-1.us-east-2.aws.neon.tech"
AKID = "nak_live_EXAMPLEKEYID0001"
SECRET = "nsk_live_EXAMPLESECRET/with+chars=0001"
BUCKET = "app-files"

SLUG = "acme"
NAMES = {
    "endpoint_secret_name": f"__axiom_prov_{SLUG}_storage_endpoint",
    "region_secret_name": f"__axiom_prov_{SLUG}_storage_region",
    "bucket_secret_name": f"__axiom_prov_{SLUG}_storage_bucket",
    "access_key_id_secret_name": f"__axiom_prov_{SLUG}_storage_access_key_id",
    "secret_access_key_secret_name": f"__axiom_prov_{SLUG}_storage_secret_access_key",
}
VALUES = {
    NAMES["endpoint_secret_name"]: ENDPOINT,
    NAMES["region_secret_name"]: "us-east-2",
    NAMES["bucket_secret_name"]: BUCKET,
    NAMES["access_key_id_secret_name"]: AKID,
    NAMES["secret_access_key_secret_name"]: SECRET,
}


def connection(**override) -> StorageConnection:
    return StorageConnection(**{**NAMES, **override})


class Ctx:
    class _Logger:
        def __init__(self, sink):
            self.sink = sink
        def debug(self, msg, **a): self.sink.append(msg)
        def info(self, msg, **a): self.sink.append(msg)
        def warn(self, msg, **a): self.sink.append(msg)
        def error(self, msg, **a): self.sink.append(msg)

    class _Secrets:
        def __init__(self, m, revoked):
            self.m, self.revoked, self.asked = m, revoked, []
        def get(self, name):
            self.asked.append(name)
            v = self.m.get(name)
            return (v, True) if v is not None else ("", False)
        def status(self, name):
            if name in self.m:
                return SecretStatus.AVAILABLE
            if name in self.revoked:
                return SecretStatus.REVOKED
            return SecretStatus.UNSET

    def __init__(self, secrets=None, revoked=()):
        self.logs = []
        self.log = self._Logger(self.logs)
        self.secrets = self._Secrets(dict(VALUES if secrets is None else secrets), set(revoked))
        self.execution_id = "test-execution-id"


class _Resp:
    def __init__(self, status, headers):
        self.status, self._h = status, headers
    def read(self): return b""
    def getheaders(self): return list(self._h.items())


class FakeConn:
    """Scripted http.client connection: each entry of `script` is either
    (status, headers) or an exception instance to raise from request()."""
    def __init__(self, script):
        self.script, self.calls, self.closed = list(script), [], 0

    def factory(self, host, timeout):
        self.calls.append({"host": host, "timeout": timeout})
        return self

    def request(self, method, uri, headers):
        self.calls[-1].update(method=method, uri=uri, headers=dict(headers))
        step = self.script.pop(0)
        if isinstance(step, BaseException):
            raise step
        self._next = step

    def getresponse(self):
        return _Resp(*self._next)

    def close(self):
        self.closed += 1
