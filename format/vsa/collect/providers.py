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
"""Concrete data sources: today's public ASF JSON, plus a file overlay that can replace any field.

ProjectsJson is the only code that knows the projects.apache.org schema. When the ASF RosterTool
or ATR provides a field instead, add a class here with the same method and pass it in Sources.
"""

import dataclasses
import pathlib
from typing import Any, Final

import vsa.collect.fetch as fetch
import vsa.collect.records as records
import vsa.document as document

PROJECTS_BASE: Final[str] = "https://projects.apache.org/json/foundation/"

_OVERLAY_KINDS: Final[dict[str, type]] = {
    "committee": records.CommitteeRecord,
    "lifecycle": records.LifecycleRecord,
    "project": records.ProjectRecord,
    "security": records.SecurityRecord,
}


class Overlay:
    """Replaces fields of another source's records with values from a JSON file.

    The file holds an object per kind ("project", "committee", "security", "lifecycle") with
    record field names as keys. A kind the inner source cannot supply at all is built from the
    file alone, so the file must then give every field.
    """

    def __init__(self, inner: records.Sources, path: str) -> None:
        self.inner = inner
        self.name = pathlib.Path(path).name
        data = document.load(path)
        unknown = sorted(set(data) - set(_OVERLAY_KINDS) - {"description"})
        if unknown:
            raise document.InputError(f"{self.name}: unknown record kinds: {', '.join(unknown)}")
        self.fields = {kind: _checked_fields(self.name, kind, data.get(kind, {})) for kind in _OVERLAY_KINDS}

    def committee(self, pmc: str) -> records.CommitteeRecord | None:
        return self._apply("committee", self.inner.roster.committee(pmc))

    def lifecycle(self, project: records.ProjectRecord) -> records.LifecycleRecord | None:
        return self._apply("lifecycle", self.inner.lifecycle.lifecycle(project))

    def project(self, key: str) -> records.ProjectRecord:
        record = self._apply("project", self.inner.projects.project(key))
        if record is None:
            raise document.InputError(f"no project record for {key}")
        return record

    def security(self, project: records.ProjectRecord) -> records.SecurityRecord | None:
        return self._apply("security", self.inner.security.security(project))

    def sources(self) -> records.Sources:
        return records.Sources(projects=self, roster=self, security=self, lifecycle=self)

    def _apply(self, kind: str, record: Any) -> Any:
        fields = self.fields[kind]
        if not fields:
            return record
        if record is None:
            return _record_from_file(self.name, kind, fields)
        return dataclasses.replace(record, **fields, source=f"{record.source} + {self.name}")


class ProjectsJson:
    """projects.json and committees.json, as published at projects.apache.org/json/foundation/."""

    def __init__(self, fetcher: fetch.Fetcher, base: str) -> None:
        self.fetcher = fetcher
        self.base = base

    def committee(self, pmc: str) -> records.CommitteeRecord | None:
        entries = self.fetcher.get_json(self.base + "committees.json")
        if not isinstance(entries, list):
            raise document.InputError("committees.json is not a list")
        entry = next((e for e in entries if isinstance(e, dict) and (e.get("id") == pmc)), None)
        if (entry is None) or (not entry.get("name")):
            return None
        roster: dict[str, Any] = entry.get("roster", {})
        chair = roster.get(entry.get("chair", ""), {})
        return records.CommitteeRecord(
            pmc=pmc,
            name=str(entry["name"]),
            chair_name=chair.get("name"),
            member_count=len(roster),
            source="committees.json",
        )

    def project(self, key: str) -> records.ProjectRecord:
        entries = self.fetcher.get_json(self.base + "projects.json")
        if (not isinstance(entries, dict)) or (key not in entries):
            raise document.InputError(f"no project {key} in {self.base}projects.json")
        entry: dict[str, Any] = entries[key]
        repositories = entry.get("repository", [])
        return records.ProjectRecord(
            key=key,
            pmc=str(entry.get("pmc") or key),
            name=entry.get("name"),
            homepage=entry.get("homepage"),
            download_page=entry.get("download-page"),
            repositories=tuple([repositories] if isinstance(repositories, str) else repositories),
            languages=_languages(entry.get("programming-language")),
            license=entry.get("license"),
            versions=tuple(str(r.get("revision", "")) for r in entry.get("release", [])),
            source="projects.json",
        )


class Unavailable:
    """Stands in for a source that does not exist yet, such as security team attestations."""

    def lifecycle(self, project: records.ProjectRecord) -> records.LifecycleRecord | None:
        return None

    def security(self, project: records.ProjectRecord) -> records.SecurityRecord | None:
        return None


def default_sources(fetcher: fetch.Fetcher, projects_base: str) -> records.Sources:
    """Today's public sources: projects.apache.org for projects and rosters, nothing else yet."""
    projects_json = ProjectsJson(fetcher, projects_base)
    unavailable = Unavailable()
    return records.Sources(projects=projects_json, roster=projects_json, security=unavailable, lifecycle=unavailable)


def _checked_fields(name: str, kind: str, fields: dict[str, Any]) -> dict[str, Any]:
    allowed = {f.name for f in dataclasses.fields(_OVERLAY_KINDS[kind])} - {"source"}
    unknown = sorted(set(fields) - allowed)
    if unknown:
        raise document.InputError(f"{name}: unknown {kind} fields: {', '.join(unknown)}")
    return {k: (tuple(v) if isinstance(v, list) else v) for k, v in fields.items()}


def _languages(value: object) -> tuple[str, ...]:
    # projects.json gives the DOAP languages as a string, a comma-separated string, a list or nothing
    if value is None:
        return ()
    items = value if isinstance(value, list) else str(value).split(",")
    return tuple(sorted({str(i).strip() for i in items if str(i).strip()}))


def _record_from_file(name: str, kind: str, fields: dict[str, Any]) -> Any:
    try:
        return _OVERLAY_KINDS[kind](**fields, source=name)
    except TypeError as e:
        raise document.InputError(f"{name}: {kind} needs every field when no other source has one: {e}") from e
