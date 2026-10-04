# christiangeorgelucas/storage-tools

Files for Axiom apps on an S3-compatible object store — built for **Neon Object
Storage** (per-branch buckets, path-style URLs, SigV4), works with any SigV4 store.
Bytes live in the bucket; the app keeps file metadata in its own rows and mints
short-lived URLs only after its own access check. URLs are never stored.

| Node | Input → Output | Network |
|---|---|---|
| `PresignPut` | `{connection, key, content_type, expires_s, max_bytes, content_length}` → `{url, method:"PUT", headers, expires_at_unix}` | none (pure signing) |
| `PresignGet` | `{connection, key, expires_s, download_name}` → `{url, expires_at_unix}` | none (pure signing) |
| `HeadObject` | `{connection, key}` → `{exists, size, content_type}` | one signed HEAD |
| `DeleteObject` | `{connection, key}` → `{ok}` | one signed DELETE |

All four are **generic templates** (`kind: generic`, `generic_ports: [input]`):
bind each per app as an Instance. The output port is inherited as published.

## Bring your own secrets

`connection` names five tenant secrets — NAMES, never values:

| slot | secret holds | Axiom app provisioned name |
|---|---|---|
| `connection.endpoint_secret_name` | `https://br-…storage.c-1.us-east-2.aws.neon.tech` (no bucket, no path) | `__axiom_prov_<slug>_storage_endpoint` |
| `connection.region_secret_name` | SigV4 region, `us-east-2` (`aws-` prefix stripped) | `__axiom_prov_<slug>_storage_region` |
| `connection.bucket_secret_name` | bare bucket name | `__axiom_prov_<slug>_storage_bucket` |
| `connection.access_key_id_secret_name` | access key id (Neon `token_id`) | `__axiom_prov_<slug>_storage_access_key_id` |
| `connection.secret_access_key_secret_name` | secret access key (Neon `s3_secret_access_key`) | `__axiom_prov_<slug>_storage_secret_access_key` |

The Instance pins the five names in its input map AND declares the same five in
its `required_secrets` — that declaration is what makes the values deliverable.
A human-held secret must be set AND dev-armed in Console → Secrets.

```yaml
# per-app instance manifest (one per generic node; same package + version)
package: <handle>/<app>-files
version: 0.1.0
generic_package: christiangeorgelucas/storage-tools
generic_node: PresignPut
generic_version: 0.1.1
nodes:
  - node: <App>PresignPut
    description: Mint an upload URL for one of <app>'s files.
    required_secrets:
      - __axiom_prov_<slug>_storage_endpoint
      - __axiom_prov_<slug>_storage_region
      - __axiom_prov_<slug>_storage_bucket
      - __axiom_prov_<slug>_storage_access_key_id
      - __axiom_prov_<slug>_storage_secret_access_key
    input:
      message: <App>PresignPutInput
      description: The object to upload.
      fields:
        key: { kind: string, description: Object key. }
        content_type: { kind: string, description: MIME type the upload must send. }
        size: { kind: int64, description: Exact upload size in bytes. }
      map:
        connection.endpoint_secret_name: "'__axiom_prov_<slug>_storage_endpoint'"
        connection.region_secret_name: "'__axiom_prov_<slug>_storage_region'"
        connection.bucket_secret_name: "'__axiom_prov_<slug>_storage_bucket'"
        connection.access_key_id_secret_name: "'__axiom_prov_<slug>_storage_access_key_id'"
        connection.secret_access_key_secret_name: "'__axiom_prov_<slug>_storage_secret_access_key'"
        key: key
        content_type: content_type
        content_length: size        # exact size, signed
        max_bytes: "10485760"       # the app's cap; refused when size exceeds it
```

## Semantics

- **Keys** are opaque caller-owned strings: 1-1024 UTF-8 bytes, no leading `/`,
  no empty / `.` / `..` segments, no control characters. The nodes never list the bucket.
- **PresignPut** signs `Content-Type` (when set) and `Content-Length` (when
  `content_length > 0`): the store refuses a body of a different type or length.
  Send `headers` exactly as returned (browsers set Content-Length themselves).
  `max_bytes` is a CEILING on `content_length`. A presigned PUT can only pin an
  exact length, never a range, so a cap needs a declared `content_length`
  (else `MAX_BYTES_REQUIRES_CONTENT_LENGTH`; over the cap, `MAX_BYTES_EXCEEDED`).
- **Always set `content_type`.** Unsigned, the uploader can store active content
  (`text/html`, `image/svg+xml`) that an inline GET renders on the storage
  origin; for untrusted uploads also pass `download_name` (attachment) on GET.
- **PresignGet** with `download_name` signs `response-content-disposition`
  (`attachment; filename="<ascii>"; filename*=UTF-8''<exact>`).
  **Neon Object Storage ignores this parameter** (verified live 2026-10-04: the
  URL works, no Content-Disposition comes back). On Neon the browser saves under
  the key's last path segment, so end keys in the file name you want.
- `expires_s` 1-604800, 0 → 600.
- **HeadObject**: 404 → `exists=false`. **DeleteObject**: a missing key is `ok=true`.
- Errors are `AxiomNodeError` with stable codes (see axiom.yaml) and never carry a secret value.

## Verification

- `axiom test`: SigV4 pinned to AWS's documented vectors (presigned GET
  `aeeed9bb…`, header-auth GET `f0e8bdb8…`, signing-key derivation) and to
  botocore-derived path-style vectors (`scripts/derive_botocore_vectors.py`).
- `nodes/live_roundtrip_test.py` (opt-in, `STORAGE_LIVE_*` env): a real
  PUT → HEAD → GET (+disposition) → DELETE round trip, plus negatives (wrong
  Content-Type, wrong length, tampered signature, expired URL, GET URL used to
  write, wrong secret → STORAGE_FORBIDDEN). Run against a local SeaweedFS S3
  gateway, and on 2026-10-04 against real Neon Object Storage through deployed
  0.1.1 Instances over provisioned app secrets: 13/14 — everything above except
  Content-Disposition, which Neon ignores.
