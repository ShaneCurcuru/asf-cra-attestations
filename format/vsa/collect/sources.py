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
"""Helpers for download directories, repository URLs and links, shared by every data source."""

import html.parser
import re
import urllib.parse
from typing import Final

import vsa.collect.fetch as fetch
import vsa.document as document

DOWNLOADS_BASE: Final[str] = "https://downloads.apache.org/"

_GITBOX_RE: Final[re.Pattern[str]] = re.compile(
    r"^https?://gitbox\.apache\.org/repos/asf/([A-Za-z0-9._-]+?)(\.git)?/?$"
)
_GITHUB_RE: Final[re.Pattern[str]] = re.compile(r"^https?://github\.com/apache/([A-Za-z0-9._-]+?)(\.git)?/?$")
_HTTP_APACHE_RE: Final[re.Pattern[str]] = re.compile(r"^http://([A-Za-z0-9.-]+\.)?apache\.org(/|$)")


class LinkParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "a":
            return
        self.hrefs.extend(value for name, value in attrs if (name == "href") and value)


def dist_files(fetcher: fetch.Fetcher, dir_url: str) -> list[str]:
    """Return the sorted absolute URLs of the files in an Apache directory listing."""
    if not dir_url.endswith("/"):
        dir_url += "/"
    body = fetcher.get(dir_url)
    if body is None:
        raise document.InputError(f"directory listing not found: {dir_url}")
    parser = LinkParser()
    parser.feed(body.decode("utf-8", errors="replace"))
    names = {h for h in parser.hrefs if not (h.startswith(("?", "/", "#")) or h.endswith("/") or ("://" in h))}
    return sorted(urllib.parse.urljoin(dir_url, n) for n in names)


def github_mirror(repositories: list[str]) -> str | None:
    """Return the GitHub mirror URL for the first gitbox or GitHub repository listed."""
    for url in repositories:
        match = _GITBOX_RE.match(url) or _GITHUB_RE.match(url)
        if match:
            return f"https://github.com/apache/{match.group(1)}"
    return None


def https(url: str | None) -> str | None:
    """Return url using https, upgrading apache.org http links, or None if it cannot be made https."""
    if not url:
        return None
    url = url.strip()
    if url.startswith("https://"):
        return url
    if _HTTP_APACHE_RE.match(url):
        return "https://" + url.removeprefix("http://")
    return None


def keys_uri(fetcher: fetch.Fetcher, pmc: str, dist_dirs: list[str]) -> str | None:
    """Return the PMC's top level KEYS file, else the one closest to the top above a release directory."""
    candidates = [f"{DOWNLOADS_BASE}{pmc}/KEYS"]
    for dir_url in dist_dirs:
        candidates.extend(_ancestor_keys(dir_url))
    for candidate in dict.fromkeys(candidates):
        if fetcher.get(candidate) is not None:
            return candidate
    return None


def _ancestor_keys(dir_url: str) -> list[str]:
    # downloads.apache.org/tomcat/tomcat-11/v11.0.27/bin/ gives KEYS candidates from the top down
    parsed = urllib.parse.urlsplit(dir_url)
    parts = [p for p in parsed.path.split("/") if p]
    root = f"{parsed.scheme}://{parsed.netloc}/"
    if parts[:1] == ["dist"]:
        root += "dist/"
        parts = parts[1:]
    return [root + "/".join(parts[:n]) + "/KEYS" for n in range(1, len(parts) + 1)]
