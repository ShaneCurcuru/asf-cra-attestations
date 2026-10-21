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
"""What changed in the answers between two attestations, for a release vote email.

Voters approve the attestation with the release, so the vote email should show every answer that
differs from the project's previous attestation, including any comment the issuer added. Release
facts that change every time (version, dates, files) are left out.
"""

import json
from typing import Any, Final

import vsa.document as document

# Top-level fields whose every change a voter should see
_ANSWER_FIELDS: Final[tuple[str, ...]] = ("template", "scope", "optOut", "issuer", "contact", "comment", "supersedes")


def changes(old: document.Document, new: document.Document) -> list[str]:
    """Return one line per changed answer, in a fixed order, or no lines when nothing changed."""
    lines: list[str] = []
    for field in _ANSWER_FIELDS:
        lines.extend(_changed(field, old.get(field), new.get(field)))
    lines.extend(_changed("subject/project", old["subject"]["project"], new["subject"]["project"]))
    for control_id in document.CONTROL_IDS:
        old_control = old["controls"].get(control_id)
        new_control = new["controls"].get(control_id)
        lines.extend(_changed(f"controls/{control_id}", old_control, new_control))
    lines.extend(_changed("inputs (settings)", _settings(old), _settings(new)))
    return lines


def _changed(name: str, old: Any, new: Any) -> list[str]:
    if old == new:
        return []
    return [f"{name}: {_text(old)} -> {_text(new)}"]


def _settings(doc: document.Document) -> list[str]:
    return [f"{i['name']} {i['sha512'][:16]}" for i in doc.get("inputs", []) if i["role"] == "settings"]


def _text(value: Any) -> str:
    if value is None:
        return "(none)"
    return json.dumps(value, ensure_ascii=False, sort_keys=True)
