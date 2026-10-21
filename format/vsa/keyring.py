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
"""Checking OpenPGP detached signatures against a KEYS file, with rpgp-py.

rpgp-py is the OpenPGP library ATR uses. It is in the optional "openpgp" extra, so that
generating and validating attestations still needs only jsonschema.

A verifier must never take its keys from the attestation it is checking, since anyone can write
an attestation. The keys come from a file the verifier chose, or from a KEYS URL under one of
the trusted prefixes.
"""

import dataclasses
import re
from collections.abc import Sequence
from typing import Any, Final

import vsa.document as document

# Where ASF KEYS files are published; a KEYS URL anywhere else is refused unless the verifier allows it
TRUSTED_KEYS_PREFIXES: Final[tuple[str, ...]] = (
    "https://downloads.apache.org/",
    "https://archive.apache.org/dist/",
    "https://dist.apache.org/repos/dist/release/",
)

_KEY_BLOCK_RE: Final[re.Pattern[str]] = re.compile(
    r"-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----", re.DOTALL
)


@dataclasses.dataclass(frozen=True)
class Keyring:
    """The public keys from one KEYS file, and where it came from, for error messages."""

    source: str
    keys: tuple[Any, ...]


def is_trusted(uri: str, prefixes: Sequence[str] = TRUSTED_KEYS_PREFIXES) -> bool:
    return any(uri.startswith(p) for p in prefixes)


def load(text: str, source: str) -> Keyring:
    """Read every public key in a KEYS file, which mixes armored key blocks with other text."""
    composed = _composed()
    keys: list[Any] = []
    for block in _KEY_BLOCK_RE.findall(text):
        try:
            keys.extend(composed.SignedPublicKey.from_armor_many(block)[0])
        except ValueError as e:
            raise document.InputError(f"{source}: unreadable public key block: {e}") from e
    if not keys:
        raise document.InputError(f"{source}: no public keys found")
    return Keyring(source, tuple(keys))


def verify(ring: Keyring, armored: bytes, data: bytes, name: str) -> str:
    """Check the detached signature over data, and return its issuer fingerprint as uppercase hex.

    The signing key, or the primary key of the signing subkey, must be in ring.
    """
    composed = _composed()
    try:
        detached = composed.DetachedSignature.from_armor(armored.decode("ascii"))[0]
    except (ValueError, UnicodeDecodeError) as e:
        raise document.InputError(f"{name}: unreadable signature: {e}") from e
    issuers = {f.upper() for f in detached.signature.issuer_fingerprint()}
    if not issuers:
        raise document.InputError(f"{name}: signature has no Issuer Fingerprint subpacket")
    candidates = [k for k in ring.keys if issuers & _fingerprints(k)]
    if not candidates:
        raise document.InputError(f"{name}: signed by {', '.join(sorted(issuers))}, which is not in {ring.source}")
    for key in candidates:
        try:
            detached.verify(key, data)
        except ValueError:
            continue
        return sorted(issuers)[0]
    raise document.InputError(f"{name}: BAD signature from {', '.join(sorted(issuers))}")


def _composed() -> Any:
    try:
        import openpgp.composed as composed
    except ImportError as e:
        raise document.InputError("checking signatures needs rpgp-py: install vsa-lite[openpgp]") from e
    return composed


def _fingerprints(key: Any) -> set[str]:
    return {key.fingerprint.upper(), *(s.key.fingerprint.upper() for s in key.public_subkeys)}
