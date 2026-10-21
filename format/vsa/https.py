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
"""HTTPS downloads with a size limit, which never follow a redirect to another host or to http."""

import http.client
import urllib.error
import urllib.parse
import urllib.request
from typing import IO, Final

import vsa.document as document

# Larger than any ASF release file today; a bigger download is refused rather than read into memory
MAX_BYTES: Final[int] = 2 * 1024 * 1024 * 1024

_CHUNK_BYTES: Final[int] = 1024 * 1024
_TIMEOUT_SECONDS: Final[int] = 60
_USER_AGENT: Final[str] = "vsa (Apache CRA attestation tooling)"


class _SameHostRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: http.client.HTTPMessage,
        newurl: str,
    ) -> urllib.request.Request | None:
        old, new = urllib.parse.urlsplit(req.full_url), urllib.parse.urlsplit(newurl)
        if (new.scheme != "https") or (new.netloc != old.netloc):
            raise document.InputError(f"refusing redirect from {req.full_url} to {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER: Final = urllib.request.build_opener(_SameHostRedirects)


def get(url: str, max_bytes: int = MAX_BYTES) -> bytes | None:
    """Return the body at url, or None when the server answers 404."""
    if not url.startswith("https://"):
        raise document.InputError(f"refusing to fetch a non-https URL: {url}")
    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with _OPENER.open(request, timeout=_TIMEOUT_SECONDS) as response:
            return _read(response, url, max_bytes)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise document.InputError(f"HTTP {e.code} from {url}") from e


def _read(response: http.client.HTTPResponse, url: str, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while chunk := response.read(_CHUNK_BYTES):
        total += len(chunk)
        if total > max_bytes:
            raise document.InputError(f"{url} is larger than {max_bytes} bytes")
        chunks.append(chunk)
    return b"".join(chunks)
