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
"""Draft project.json and release-X.json files for vsa generate, with a report of what is left to answer."""

import dataclasses
import fnmatch
import pathlib
import re
import urllib.parse
from typing import Any, Final

import vsa.collect.fetch as fetch
import vsa.collect.records as records
import vsa.collect.resolve as resolve
import vsa.collect.sources as sources
import vsa.document as document

_ARCHIVE_EXTENSIONS: Final[tuple[str, ...]] = (".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip", ".jar", ".war")
_DOC_RE: Final[re.Pattern[str]] = re.compile(r"[-_.](full)?docs?([-_.]|$)|javadoc", re.IGNORECASE)
_SBOM_SUFFIXES: Final[dict[str, str]] = {
    ".cdx.json": "CycloneDX",
    "-cyclonedx.json": "CycloneDX",
    ".spdx.json": "SPDX",
    "-spdx.json": "SPDX",
}
_ASF_DIST_HOSTS: Final[frozenset[str]] = frozenset({"archive.apache.org", "dist.apache.org", "downloads.apache.org"})
# File types treated as released artifacts, following Whimsy's download page checker
_ARTIFACT_SUFFIXES: Final[tuple[str, ...]] = (
    ".crate",
    ".deb",
    ".dmg",
    ".exe",
    ".far",
    ".jar",
    ".msi",
    ".nar",
    ".nbm",
    ".rar",
    ".rpm",
    ".sh",
    ".tar",
    ".tar.bz2",
    ".tar.gz",
    ".tar.xz",
    ".tgz",
    ".vsix",
    ".war",
    ".whl",
    ".zip",
)
_SOURCE_RE: Final[re.Pattern[str]] = re.compile(r"[-_.](src|source|sources|source-release)([-_.]|$)", re.IGNORECASE)


@dataclasses.dataclass(frozen=True)
class Options:
    """What the person running the collector chose."""

    key: str
    version: str | None = None
    ref: str | None = None
    git_url: str | None = None
    dist_dirs: tuple[str, ...] = ()
    # The parent written into the draft, as the person gave it
    parent: str | None = None
    # The settings files the draft inherits, root first, such as the ASF baseline then a community baseline
    baselines: tuple[str, ...] = ()
    # "name" or "role": whether AU.02 publishes the chair's name, written into the draft when given
    contact_style: str | None = None


def has_version(url: str, version: str) -> bool:
    """Return whether the file name in url carries exactly version."""
    # 1.2.3 must not match 1.2.30 or 11.2.3
    pattern = rf"(?<![0-9.]){re.escape(version)}(?![0-9]|\.[0-9])"
    return re.search(pattern, _name(url)) is not None


def local_id(url: str, version: str) -> str:
    """Return the document-local ID for the file at url."""
    # The version is left out so that IDs, and project.json references to them, stay the same across releases
    name = _name(url).replace(version, "").lower()
    name = re.sub(r"[^a-z0-9._-]", "-", name)
    name = re.sub(r"-+", "-", name).replace("-.", ".")
    return name.strip("._-")


def project_draft(
    fetcher: fetch.Fetcher, data: records.Sources, options: Options
) -> tuple[document.Document, document.Document]:
    """Return a draft project.json and a report naming the source of every value and every gap.

    Project, roster, security and lifecycle data come from data, so each can be swapped for another
    source; fetcher is used only for download directories and the git repository.
    """
    facts, keys = _facts(fetcher, data, options)
    resolutions = _apply_baselines(resolve.all_controls(facts), options.baselines)
    draft, field_report = _project_fields(facts, keys, options.contact_style)
    if options.parent is not None:
        draft = {"description": draft.pop("description"), "parent": options.parent, **draft}
    draft["controls"] = {c: r.control for c, r in resolutions.items() if r.control is not None}
    report: document.Document = {
        "project": options.key,
        "pmc": facts.project.pmc,
        "sources": _record_sources(facts),
        "repository": {"url": facts.repo_url, "ref": facts.ref, "commit": facts.commit},
        "fields": field_report,
        "controls": {c: _report_entry(r) for c, r in resolutions.items()},
        "toAnswer": [c for c, r in resolutions.items() if r.result == resolve.NEEDS_ANSWER]
        + [f for f, e in field_report.items() if e["result"] == resolve.NEEDS_ANSWER],
        "responses": fetcher.responses(),
    }
    return draft, report


def release_draft(
    fetcher: fetch.Fetcher,
    version: str,
    issued: str,
    dist_dirs: tuple[str, ...],
    extra: dict[str, str],
    source_globs: tuple[str, ...] = (),
) -> document.Document:
    """Return a release-X.json naming every artifact, signature and SBOM for version in dist_dirs.

    Source packages are found by name (-src, -source and similar), or by source_globs when given.
    """
    files = sorted({f for d in dist_dirs for f in sources.dist_files(fetcher, d)})
    names = {_name(f) for f in files}
    release_files = [f for f in files if has_version(f, version)]
    sbom_files = [f for f in release_files if _sbom_format(f)]
    artifact_files = [f for f in release_files if _name(f).lower().endswith(_ARTIFACT_SUFFIXES)]
    if not artifact_files:
        raise document.InputError(f"no files for version {version} in {', '.join(dist_dirs)}")
    # extra carries the optional releaseDate, tag and commit, in that order
    doc: document.Document = {"version": version, **extra, "issued": issued}
    doc["artifacts"] = [_artifact(f, names, sbom_files, version, source_globs) for f in artifact_files]
    if not any(a["official"] for a in doc["artifacts"]):
        raise document.InputError(
            "no source package from the ASF distribution area found by name; "
            "name it with --source, for example 'httpd-*.tar.gz'"
        )
    if sbom_files:
        doc["sboms"] = [_sbom(f, names, version) for f in sbom_files]
    return doc


def sbom_ids(fetcher: fetch.Fetcher, dist_dirs: tuple[str, ...], version: str) -> tuple[str, ...]:
    """Return the IDs release_draft gives the SBOMs published for version."""
    if (not dist_dirs) or (not version):
        return ()
    files = sorted({f for d in dist_dirs for f in sources.dist_files(fetcher, d)})
    return tuple(local_id(f, version) for f in files if has_version(f, version) and _sbom_format(f))


def _apply_baselines(
    resolutions: dict[str, resolve.Resolution], baseline_paths: tuple[str, ...]
) -> dict[str, resolve.Resolution]:
    # A baseline answer is never overridden by a collected one, since a project answer replaces it whole
    if not baseline_paths:
        return resolutions
    owners: dict[str, str] = {}
    for path in baseline_paths:
        owners.update(dict.fromkeys(document.load(path).get("controls", {}), pathlib.Path(path).name))
    return {c: _baseline_resolution(r, owners.get(c)) for c, r in resolutions.items()}


def _artifact(
    url: str, names: set[str], sbom_files: list[str], version: str, source_globs: tuple[str, ...]
) -> document.Document:
    name = _name(url)
    role = _role(url, source_globs)
    # Only a source package in the ASF distribution area is the voted, official release
    official = (role == "source") and (urllib.parse.urlsplit(url).hostname in _ASF_DIST_HOSTS)
    out: document.Document = {"id": local_id(url, version), "name": name, "role": role, "official": official}
    out["uri"] = url
    out["signatureUri"] = _signature(url, names)
    refs = [local_id(s, version) for s in sbom_files if _sbom_subject(s) in (name, _stem(name))]
    if refs:
        out["sbomRefs"] = refs
    return out


def _baseline_resolution(resolution: resolve.Resolution, owner: str | None) -> resolve.Resolution:
    if owner is not None:
        uris = [e["uri"] for e in (resolution.control or {}).get("evidence", []) if "uri" in e]
        found = f" The collector also found: {', '.join(uris)}." if uris else ""
        return resolve.Resolution(resolve.BASELINE, owner, f"Answered by {owner}.{found}")
    if resolution.result == resolve.BASELINE:
        return resolve.Resolution(resolve.NEEDS_ANSWER, "", "Expected in a baseline, but no baseline given answers it.")
    return resolution


def _contact(facts: resolve.Facts, style: str | None) -> document.Document | None:
    # AU.02 names the PMC chair, as the official representative of the PMC (Shane, 2026-10-15)
    # TODO: Ask whether a PMC may instead name the release manager, as the person who ran the build
    committee = facts.committee
    if committee is None:
        return None
    role = {"role": f"Vice President, {committee.name}", "email": f"private@{committee.pmc}.apache.org"}
    # A PMC may publish its chair by role alone (Shane, 2026-10-21)
    if style == "role":
        return role
    if not committee.chair_name:
        return None
    return {"name": committee.chair_name, **role}


def _facts(fetcher: fetch.Fetcher, data: records.Sources, options: Options) -> tuple[resolve.Facts, str | None]:
    project = data.projects.project(options.key)
    repo_url = _repo_url(project, options)
    commit: str | None = None
    paths: tuple[str, ...] = ()
    if (repo_url is not None) and (options.ref is not None):
        commit, tree = fetcher.git_tree(repo_url + ".git", options.ref)
        paths = tuple(tree)
    facts = resolve.Facts(
        project=project,
        committee=data.roster.committee(project.pmc),
        security=data.security.security(project),
        lifecycle=data.lifecycle.lifecycle(project),
        repo_url=repo_url if paths else None,
        ref=options.ref if paths else None,
        commit=commit,
        paths=paths,
        sbom_ids=sbom_ids(fetcher, options.dist_dirs, options.version or ""),
    )
    return facts, sources.keys_uri(fetcher, project.pmc, list(options.dist_dirs))


def _field(result: str, source: str, note: str = "") -> dict[str, str]:
    return {"result": result, "source": source, "note": note}


def _name(url: str) -> str:
    return urllib.parse.unquote(url.rsplit("/", 1)[-1])


def _other_role(name: str) -> str:
    return "documentation" if _DOC_RE.search(name) else "binary"


def _project_fields(
    facts: resolve.Facts, keys: str | None, contact_style: str | None
) -> tuple[document.Document, dict[str, dict[str, str]]]:
    project = facts.project
    draft: document.Document = {
        "description": "Draft written by vsa-collect. Review every value and answer the controls the report lists.",
    }
    report: dict[str, dict[str, str]] = {}
    homepage = sources.https(project.homepage)
    if project.name and homepage:
        draft["project"] = {"name": project.name, "url": homepage}
        report["project"] = _field(resolve.COLLECTED, project.source)
    else:
        report["project"] = _field(resolve.NEEDS_ANSWER, project.source, "No name or https homepage.")
    committee_name = facts.committee.name if facts.committee else f"Apache {project.pmc}"
    draft["pmc"] = f"{committee_name} PMC"
    roster_source = facts.committee.source if facts.committee else "roster"
    _set(draft, report, "contact", _contact(facts, contact_style), roster_source, "No PMC chair found.")
    _set(draft, report, "vcs", _vcs(project), project.source, "No https source repository.")
    _set(draft, report, "keysUri", keys, "downloads.apache.org", "No KEYS file found.")
    if contact_style is not None:
        draft["attestation"] = {"contactStyle": contact_style}
    return draft, report


def _record_sources(facts: resolve.Facts) -> dict[str, str | None]:
    return {
        "project": facts.project.source,
        "committee": facts.committee.source if facts.committee else None,
        "security": facts.security.source if facts.security else None,
        "lifecycle": facts.lifecycle.source if facts.lifecycle else None,
    }


def _repo_url(project: records.ProjectRecord, options: Options) -> str | None:
    if options.git_url:
        return options.git_url.removesuffix(".git").rstrip("/")
    return sources.github_mirror(list(project.repositories))


def _report_entry(resolution: resolve.Resolution) -> dict[str, str]:
    return _field(resolution.result, resolution.source, resolution.note)


def _role(url: str, source_globs: tuple[str, ...]) -> str:
    name = _name(url)
    if source_globs:
        return "source" if any(fnmatch.fnmatchcase(name, g) for g in source_globs) else _other_role(name)
    if _SOURCE_RE.search(name) or ("/source/" in url) or ("/src/" in url):
        return "source"
    return _other_role(name)


def _sbom(url: str, names: set[str], version: str) -> document.Document:
    out: document.Document = {"id": local_id(url, version), "format": _sbom_format(url), "uri": url}
    if f"{_name(url)}.asc" in names:
        out["signatureUri"] = f"{url}.asc"
    return out


def _sbom_format(url: str) -> str | None:
    name = _name(url).lower()
    return next((fmt for suffix, fmt in _SBOM_SUFFIXES.items() if name.endswith(suffix)), None)


def _sbom_subject(url: str) -> str:
    # commons-lang3-3.17.0-cyclonedx.json describes commons-lang3-3.17.0.jar, whose stem it repeats
    name = _name(url)
    suffix = next(s for s in _SBOM_SUFFIXES if name.lower().endswith(s))
    return name[: -len(suffix)]


def _set(draft: document.Document, report: dict[str, Any], field: str, value: object, source: str, gap: str) -> None:
    if value is None:
        report[field] = _field(resolve.NEEDS_ANSWER, source, gap)
        return
    draft[field] = value
    report[field] = _field(resolve.COLLECTED, source)


def _signature(url: str, names: set[str]) -> str:
    # ASF release policy requires a detached signature for every released file
    if f"{_name(url)}.asc" not in names:
        raise document.InputError(f"no .asc signature next to {url}")
    return f"{url}.asc"


def _stem(name: str) -> str:
    for extension in _ARCHIVE_EXTENSIONS:
        if name.endswith(extension):
            return name.removesuffix(extension)
    return name


def _vcs(project: records.ProjectRecord) -> document.Document | None:
    for url in project.repositories:
        secure = sources.https(url)
        if secure is None:
            continue
        kind = "svn" if ("svn." in secure) else "git"
        return {"type": kind, "url": secure}
    return None
