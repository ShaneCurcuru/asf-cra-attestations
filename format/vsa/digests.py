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
"""Computing and checking the digests of release files."""

import hashlib
import pathlib
import urllib.request
from typing import Final

import vsa.document as document

ALGORITHMS: Final[tuple[str, ...]] = ("sha512",)

_URL_TIMEOUT_SECONDS: Final[int] = 60


def compute(data: bytes) -> dict[str, str]:
    return {alg: hashlib.new(alg, data).hexdigest() for alg in ALGORITHMS}


def verify(doc: document.Document, local_dir: str | None = None) -> list[str]:
    """Hash every artifact and SBOM and compare the results to the recorded digests and sizes."""
    errors: list[str] = []
    for item in doc["subject"]["artifacts"] + doc["subject"].get("sboms", []):
        errors.extend(_verify_item(item, _fetch(item["uri"], local_dir)))
    return errors


def _fetch(uri: str, local_dir: str | None) -> bytes:
    if local_dir:
        path = pathlib.Path(local_dir) / uri.rsplit("/", 1)[-1]
        if path.exists():
            return path.read_bytes()
    if not uri.startswith("https://"):
        raise document.InputError(f"refusing to fetch non HTTPS URI {uri}")
    with urllib.request.urlopen(uri, timeout=_URL_TIMEOUT_SECONDS) as response:
        return response.read()


def _verify_item(item: document.Document, data: bytes) -> list[str]:
    errors: list[str] = []
    for alg, expected in item["digests"].items():
        actual = hashlib.new(alg.replace("-", "_"), data).hexdigest()
        if actual != expected:
            errors.append(f"{item['id']}: {alg} mismatch for {item['uri']}")
    if ("size" in item) and (item["size"] != len(data)):
        errors.append(f"{item['id']}: size {len(data)} != {item['size']}")
    return errors
