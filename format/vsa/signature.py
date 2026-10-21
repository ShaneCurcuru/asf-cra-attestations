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
"""Reading key fingerprints from OpenPGP detached signatures, without verifying them."""

import base64
from typing import Final

import vsa.document as document

_ARMOR_BEGIN: Final[str] = "-----BEGIN PGP SIGNATURE-----"
_ARMOR_END: Final[str] = "-----END PGP SIGNATURE-----"
_ISSUER_FINGERPRINT_SUBPACKET: Final[int] = 33
_SIGNATURE_TAG: Final[int] = 2
_SUPPORTED_VERSIONS: Final[frozenset[int]] = frozenset({4, 5, 6})


def fingerprint(armored: bytes) -> str:
    """Return the issuer fingerprint, as uppercase hex, of an ASCII armored detached signature.

    This reads the Issuer Fingerprint subpacket (RFC 9580, type 33) of a v4, v5 or v6 signature.
    It identifies the key only, and does not check the signature.
    """
    try:
        data = _armor_payload(armored.decode("ascii"))
        i = _body_offset(data)
        version = data[i]
        if version not in _SUPPORTED_VERSIONS:
            raise document.InputError(f"unsupported signature packet version {version}")
        # Skip the version, signature type, public key algorithm, and hash algorithm octets
        i += 4
        count_length = 4 if (version == 6) else 2
        hashed_length = int.from_bytes(data[i : i + count_length], "big")
        i += count_length
        return _subpacket_fingerprint(data[i : i + hashed_length])
    except (IndexError, UnicodeDecodeError, ValueError) as e:
        raise document.InputError(f"malformed OpenPGP signature: {e}") from e


def _armor_payload(armored: str) -> bytes:
    lines = armored.strip().splitlines()
    if _ARMOR_BEGIN not in lines:
        raise document.InputError("not an ASCII armored OpenPGP signature")
    start = lines.index(_ARMOR_BEGIN) + 1
    # Armor headers run up to the first blank line
    while lines[start].strip():
        start += 1
    body: list[str] = []
    for line in lines[start + 1 :]:
        if line.startswith("=") or line.startswith(_ARMOR_END):
            break
        body.append(line.strip())
    return base64.b64decode("".join(body))


def _body_offset(data: bytes) -> int:
    tag_octet = data[0]
    if tag_octet & 0x40:
        tag = tag_octet & 0x3F
        first = data[1]
        length_octets = 1 if (first < 192) else (2 if (first < 224) else 5)
        offset = 1 + length_octets
    else:
        tag = (tag_octet >> 2) & 0x0F
        offset = 1 + {0: 1, 1: 2, 2: 4}.get(tag_octet & 0x03, 0)
    if tag != _SIGNATURE_TAG:
        raise document.InputError("first packet is not a signature packet")
    return offset


def _subpacket_fingerprint(hashed: bytes) -> str:
    i = 0
    while i < len(hashed):
        first = hashed[i]
        if first < 192:
            length, i = first, i + 1
        elif first < 255:
            length, i = ((first - 192) << 8) + hashed[i + 1] + 192, i + 2
        else:
            length, i = int.from_bytes(hashed[i + 1 : i + 5], "big"), i + 5
        if (hashed[i] & 0x7F) == _ISSUER_FINGERPRINT_SUBPACKET:
            # Skip the subpacket type octet and the key version octet
            return hashed[i + 2 : i + length].hex().upper()
        i += length
    raise document.InputError("signature has no Issuer Fingerprint subpacket, so re-sign with a modern gpg")
