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
"""Network access for the collector, with a cache that makes every run repeatable.

Every response, including a 404, is stored in the cache directory keyed by URL.
An offline run reads only from the cache, so the same cache always gives the same draft.

The cache is plain files that anyone with write access to its directory can change, so the
fetcher keeps the SHA-512 of every response it used, cached or not, and the report lists them.
That records exactly which data a draft was built from.
"""

import hashlib
import json
import pathlib
import subprocess
import tempfile

import vsa.digests as digests
import vsa.document as document
import vsa.https as https


class Fetcher:
    """Fetches HTTPS documents and git trees, through an optional cache directory."""

    def __init__(self, cache_dir: pathlib.Path | None, offline: bool) -> None:
        if offline and (cache_dir is None):
            raise document.InputError("an offline run needs a cache directory")
        self.cache_dir = cache_dir
        self.offline = offline
        # Each key used, with its status and the SHA-512 of its body
        self.used: dict[str, tuple[int, str]] = {}

    def get(self, url: str) -> bytes | None:
        """Return the body at url, or None when the server answers 404."""
        cached = self._read_cache(url)
        if cached is not None:
            self._use(url, *cached)
            return cached[1] if cached[0] == 200 else None
        if self.offline:
            raise document.InputError(f"offline, and not in the cache: {url}")
        body = https.get(url)
        status = 404 if (body is None) else 200
        self.record(url, status, body or b"")
        self._use(url, status, body or b"")
        return body

    def get_json(self, url: str) -> object:
        body = self.get(url)
        if body is None:
            raise document.InputError(f"not found: {url}")
        return json.loads(body)

    def git_tree(self, repo_url: str, ref: str) -> tuple[str, list[str]]:
        """Return the commit ID of ref and the sorted paths of every file in it."""
        key = f"git:{repo_url}#{ref}"
        cached = self._read_cache(key)
        if cached is not None:
            self._use(key, *cached)
            if cached[0] != 200:
                raise document.InputError(f"ref {ref} not found in {repo_url}")
            lines = cached[1].decode("utf-8").splitlines()
            return lines[0], lines[1:]
        if self.offline:
            raise document.InputError(f"offline, and not in the cache: {key}")
        commit, paths = _git_tree(repo_url, ref)
        body = "\n".join([commit, *paths]).encode("utf-8")
        self.record(key, 200, body)
        self._use(key, 200, body)
        return commit, paths

    def responses(self) -> list[document.Document]:
        """Return every response used so far, sorted by key, with its status and the SHA-512 of its body."""
        return [{"key": k, "status": st, "sha512": sha} for k, (st, sha) in sorted(self.used.items())]

    def record(self, key: str, status: int, body: bytes) -> None:
        """Store a response in the cache, which is also how a cache can be seeded by hand."""
        if self.cache_dir is None:
            return
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        meta_path, body_path = _cache_paths(self.cache_dir, key)
        body_path.write_bytes(body)
        meta_path.write_text(json.dumps({"key": key, "status": status}, indent=2) + "\n", encoding="utf-8")

    def _read_cache(self, key: str) -> tuple[int, bytes] | None:
        if self.cache_dir is None:
            return None
        meta_path, body_path = _cache_paths(self.cache_dir, key)
        if not meta_path.is_file():
            return None
        status = json.loads(meta_path.read_text(encoding="utf-8"))["status"]
        return status, body_path.read_bytes()

    def _use(self, key: str, status: int, body: bytes) -> None:
        self.used[key] = (status, digests.sha512(body))


def _cache_paths(cache_dir: pathlib.Path, key: str) -> tuple[pathlib.Path, pathlib.Path]:
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]
    return cache_dir / f"{digest}.json", cache_dir / f"{digest}.body"


def _fetch_ref(repo_url: str, ref: str, work: str) -> None:
    # Tags such as rel/commons-lang3-3.17.0 are only found by their full name
    refs = [ref] if ref.startswith("refs/") else [f"refs/tags/{ref}", ref]
    for candidate in refs[:-1]:
        try:
            _git(["fetch", "--quiet", "--depth=1", "--filter=blob:none", repo_url, candidate], work)
            return
        except document.InputError:
            continue
    _git(["fetch", "--quiet", "--depth=1", "--filter=blob:none", repo_url, refs[-1]], work)


def _git(args: list[str], cwd: str) -> str:
    result = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise document.InputError(f"git {args[0]} failed: {result.stderr.strip()}")
    return result.stdout


def _git_tree(repo_url: str, ref: str) -> tuple[str, list[str]]:
    # A blobless shallow fetch reads the file list without downloading file contents
    if not repo_url.startswith("https://"):
        raise document.InputError(f"refusing to fetch a non-https repository: {repo_url}")
    with tempfile.TemporaryDirectory() as work:
        _git(["init", "--quiet"], work)
        _fetch_ref(repo_url, ref, work)
        commit = _git(["rev-parse", "FETCH_HEAD^{commit}"], work).strip()
        paths = _git(["ls-tree", "-r", "--name-only", "FETCH_HEAD"], work).splitlines()
    return commit, sorted(paths)
