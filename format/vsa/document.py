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
"""The attestation document: schema checks, loading and serialisation."""

import json
import pathlib
from typing import Any, Final

import jsonschema

SCHEMA_PATH: Final[pathlib.Path] = pathlib.Path(__file__).resolve().parent / "schema" / "vsa-lite.schema.json"

_SCHEMA: Final[dict[str, Any]] = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

# The checklist and version come from the schema alone, so a new template or version needs only a schema change
CONTROL_IDS: Final[tuple[str, ...]] = tuple(_SCHEMA["$defs"]["controls"]["required"])
SCHEMA_VERSION: Final[str] = _SCHEMA["properties"]["schemaVersion"]["const"]

Document = dict[str, Any]


class InputError(Exception):
    pass


def check(doc: Document) -> list[str]:
    """Return a list of error strings, which is empty when doc is valid."""
    validator = jsonschema.Draft202012Validator(_SCHEMA, format_checker=jsonschema.FormatChecker())
    schema_errors = sorted(validator.iter_errors(doc), key=lambda e: [str(p) for p in e.absolute_path])
    if schema_errors:
        return [f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}" for e in schema_errors]
    return _check_references(doc)


def dump(doc: Document) -> str:
    """Serialise doc deterministically, with a trailing newline."""
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def load(path: str | pathlib.Path) -> Document:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _check_references(doc: Document) -> list[str]:
    subject = doc["subject"]
    artifact_ids = [a["id"] for a in subject["artifacts"]]
    sbom_ids = [s["id"] for s in subject.get("sboms", [])]
    all_ids = artifact_ids + sbom_ids
    errors = [f"subject: id '{i}' is used more than once" for i in sorted({i for i in all_ids if all_ids.count(i) > 1})]
    for artifact in subject["artifacts"]:
        errors.extend(
            f"artifact '{artifact['id']}': sbomRefs '{ref}' is not a subject.sboms id"
            for ref in artifact.get("sbomRefs", [])
            if ref not in sbom_ids
        )
    for control_id, control in doc["controls"].items():
        errors.extend(
            f"controls/{control_id}: evidence ref '{ev['ref']}' does not resolve"
            for ev in control.get("evidence", [])
            if ("ref" in ev) and (ev["ref"] not in all_ids)
        )
    if (doc["controls"]["QA.01"]["status"] == "met") and (not sbom_ids):
        errors.append("controls/QA.01: met, but subject.sboms is empty")
    if not any(a.get("official") for a in subject["artifacts"]):
        errors.append("subject.artifacts: no artifact is marked official")
    return errors
