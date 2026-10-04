"""Derive the cross-check vectors pinned in nodes/storage_core_test.py from
botocore's own SigV4 presigner, path-style, with the clock frozen.

Run (needs `pip install botocore`; botocore is a TEST-TIME witness only, never
a runtime dependency):  python3 scripts/derive_botocore_vectors.py
"""
import datetime
import json
from unittest import mock

import botocore.session
from botocore.config import Config

NOW = datetime.datetime(2026, 10, 4, 12, 30, 45)
ENDPOINT = "https://br-cool-tree-a1b2c3.storage.c-1.us-east-2.aws.neon.tech"
AKID = "nak_live_EXAMPLEKEYID0001"
SECRET = "nsk_live_EXAMPLESECRET/with+chars=0001"
BUCKET = "app-files"


def client():
    s = botocore.session.get_session()
    return s.create_client(
        "s3", region_name="us-east-2", endpoint_url=ENDPOINT,
        aws_access_key_id=AKID, aws_secret_access_key=SECRET,
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
    )


def main():
    c = client()
    out = {}
    with mock.patch("botocore.auth.get_current_datetime", return_value=NOW):
        out["put_plain"] = c.generate_presigned_url(
            "put_object", Params={"Bucket": BUCKET, "Key": "acme/notes/42/7/report q3.pdf"}, ExpiresIn=600)
        out["put_typed_sized"] = c.generate_presigned_url(
            "put_object", Params={"Bucket": BUCKET, "Key": "acme/photos/9/1/café.png",
                                  "ContentType": "image/png", "ContentLength": 1024}, ExpiresIn=900)
        out["get_plain"] = c.generate_presigned_url(
            "get_object", Params={"Bucket": BUCKET, "Key": "acme/notes/42/7/report q3.pdf"}, ExpiresIn=600)
        out["get_disposition"] = c.generate_presigned_url(
            "get_object", Params={"Bucket": BUCKET, "Key": "a/b/c.txt",
                                  "ResponseContentDisposition":
                                      "attachment; filename=\"r_sum_.txt\"; filename*=UTF-8''r%C3%A9sum%C3%A9.txt"},
            ExpiresIn=3600)
    print(json.dumps(out, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()


def header_vectors():
    """Authorization headers for the bodiless HEAD/DELETE calls, from
    botocore's S3SigV4Auth (which sends UNSIGNED-PAYLOAD over https)."""
    from botocore.auth import S3SigV4Auth
    from botocore.awsrequest import AWSRequest
    from botocore.credentials import Credentials

    creds = Credentials(AKID, SECRET)
    out = {}
    with mock.patch("botocore.auth.get_current_datetime", return_value=NOW):
        for method in ("HEAD", "DELETE"):
            req = AWSRequest(method=method, url=f"{ENDPOINT}/{BUCKET}/acme/notes/42/7/report%20q3.pdf")
            S3SigV4Auth(creds, "s3", "us-east-2").add_auth(req)
            out[method] = {k: v for k, v in req.headers.items()}
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    header_vectors()
