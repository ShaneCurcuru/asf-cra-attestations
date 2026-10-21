# OpenPGP test data

Test keys for the signature tests in `tests/test_verify.py`. They are not ASF keys, sign nothing
outside these tests, and expire on 2036-01-01. Their secret keys were deleted after signing.

| File | What it is |
| --- | --- |
| `KEYS` | "VSA Test Release Manager": a certify-only primary key with an Ed25519 signing subkey |
| `OTHER-KEYS` | "VSA Test Outsider": a key that is not in `KEYS` |
| `hello.txt`, `hello.cdx.json` | The test release: a source file and a CycloneDX SBOM |
| `hello.txt.asc` | Signature over `hello.txt` by the `KEYS` subkey |
| `hello.txt.outsider.asc` | Signature over `hello.txt` by the outsider key |
| `release-1.0.json` | Release inputs naming those files |
| `hello-1.0.vsa.json` | The attestation `vsa generate` writes from them (a golden file) |
| `hello-1.0.vsa.json.asc` | Signature over that attestation by the `KEYS` subkey |
