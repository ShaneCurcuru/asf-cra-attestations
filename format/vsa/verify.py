# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""Checking an attestation against the release files: digests, sizes and OpenPGP signatures.

Files are read from a local directory when they are there, and otherwise downloaded from their
URI. When a URI no longer answers, each mirror is tried in turn, because ASF releases move from
downloads.apache.org to archive.apache.org when a newer release replaces them. A file is accepted
by its digest, never by where it came from.
"""

import hashlib
import pathlib
from collections.abc import Mapping, Sequence
from typing import Final

import vsa.document as document
import vsa.https as https
import vsa.keyring as keyring

# Each pair is a URI prefix and the prefix to try in its place when the first gives 404
MIRRORS: Final[tuple[tuple[str, str], ...]] = (("https://downloads.apache.org/", "https://archive.apache.org/dist/"),)


def fetch(uri: str, local_dir: str | None, mirrors: Sequence[tuple[str, str]] = MIRRORS) -> bytes:
    """Return the file named by uri, from local_dir if it holds a file of that name, else downloaded."""
    if local_dir:
        path = pathlib.Path(local_dir) / uri.rsplit("/", 1)[-1]
        if path.is_file():
            return path.read_bytes()
    candidates = [uri, *(new + uri.removeprefix(old) for old, new in mirrors if uri.startswith(old))]
    for candidate in candidates:
        body = https.get(candidate)
        if body is not None:
            return body
    raise document.InputError(f"not found at {', '.join(candidates)}")


def files(
    doc: document.Document,
    local_dir: str | None,
    rings: Mapping[str, keyring.Keyring] | None,
    mirrors: Sequence[tuple[str, str]] = MIRRORS,
) -> list[str]:
    """Hash every artifact and SBOM, compare them to the recorded values, and check each signature.

    rings maps each keysUri in the document to the keys its signatures must verify against. When
    rings is None, signatures are not checked, and the caller must say so.
    """
    errors: list[str] = []
    for item in doc["subject"]["artifacts"] + doc["subject"].get("sboms", []):
        data = fetch(item["uri"], local_dir, mirrors)
        errors.extend(_digest_errors(item, data))
        if (rings is not None) and ("signature" in item):
            errors.extend(_signature_errors(item, data, local_dir, rings, mirrors))
    return errors


def keys_uris(doc: document.Document) -> list[str]:
    """Return every KEYS URL the document's OpenPGP signatures name, sorted."""
    items = doc["subject"]["artifacts"] + doc["subject"].get("sboms", [])
    return sorted({i["signature"]["keysUri"] for i in items if i.get("signature", {}).get("format") == "openpgp"})


def _digest_errors(item: document.Document, data: bytes) -> list[str]:
    errors: list[str] = []
    for alg, expected in item["digests"].items():
        actual = hashlib.new(alg.replace("-", "_"), data).hexdigest()
        if actual != expected:
            errors.append(f"{item['id']}: {alg} mismatch for {item['uri']}")
    if ("size" in item) and (item["size"] != len(data)):
        errors.append(f"{item['id']}: size {len(data)} != {item['size']}")
    return errors


def _signature_errors(
    item: document.Document,
    data: bytes,
    local_dir: str | None,
    rings: Mapping[str, keyring.Keyring],
    mirrors: Sequence[tuple[str, str]],
) -> list[str]:
    block = item["signature"]
    if block["format"] != "openpgp":
        return [f"{item['id']}: cannot check {block['format']} signatures"]
    try:
        fingerprint = keyring.verify(rings[block["keysUri"]], fetch(block["uri"], local_dir, mirrors), data, item["id"])
    except document.InputError as e:
        return [str(e)]
    if fingerprint != block["keyFingerprint"]:
        return [f"{item['id']}: signed by {fingerprint}, but the attestation records {block['keyFingerprint']}"]
    return []
