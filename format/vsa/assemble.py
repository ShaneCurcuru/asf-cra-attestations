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
"""Assembling an attestation from layered settings, release inputs and the release files."""

import datetime
import json
import pathlib
import uuid
from collections.abc import Sequence
from typing import Final

import vsa.digests as digests
import vsa.document as document
import vsa.settings as settings
import vsa.signature as signature

_OPT_OUT_FIELDS: Final[tuple[str, ...]] = ("reason", "statement", "decided", "decisionRef", "reviewBy")


def attestation(
    layers: Sequence[settings.Layer],
    release: document.Document,
    directory: str,
) -> document.Document:
    """Merge the settings layers, the release inputs and the release files in directory into one attestation.

    layers runs root first, as settings.chain returns it: at the ASF, the ASF baseline, then any
    community baseline, then the project or product file. A later layer replaces an earlier layer's
    control with the same ID, whole, unless an earlier layer requires it (see vsa.settings).
    When the settings opt out, every control that is still unanswered becomes not_assessed.
    The same inputs and files always give the same document.
    """
    project = settings.merge(layers)
    keys_uri = project["keysUri"]
    opt_out = _opt_out(project, release)
    # Check every answer before reading any release file, so input errors are reported first
    controls = _controls(project.get("controls", {}), minimal=(opt_out is not None))
    doc: document.Document = {
        "schemaVersion": document.SCHEMA_VERSION,
        "template": project["template"],
        "attestationId": _attestation_id(project, release),
        "scope": "full" if (opt_out is None) else "minimal",
    }
    if opt_out is not None:
        doc["optOut"] = opt_out
    doc["issued"] = release["issued"]
    for key in ("validUntil", "supersedes", "comment"):
        if key in release:
            doc[key] = release[key]
    doc["issuer"] = _issuer(project)
    # AU.02 names the PMC chair, as the official representative of the PMC
    # TODO: Ask whether a PMC may optionally name the release manager instead, as the person who ran the build
    doc["contact"] = project["contact"]
    doc["subject"] = {
        "project": project["project"],
        "release": _release(project, release),
        "artifacts": [_artifact(a, directory, keys_uri) for a in release["artifacts"]],
    }
    sboms = [_sbom(s, directory, keys_uri) for s in release.get("sboms", [])]
    if sboms:
        doc["subject"]["sboms"] = sboms
    doc["controls"] = controls
    return doc


def _artifact(artifact: document.Document, directory: str, keys_uri: str) -> document.Document:
    data = _local_file(directory, artifact["uri"])
    out = {k: artifact[k] for k in ("id", "name", "role", "official", "uri", "purl") if k in artifact}
    out["size"] = len(data)
    out["digests"] = digests.compute(data)
    if "signatureUri" in artifact:
        out["signature"] = _signature_block(directory, artifact["signatureUri"], keys_uri)
    if "sbomRefs" in artifact:
        out["sbomRefs"] = artifact["sbomRefs"]
    return out


def _attestation_id(project: document.Document, release: document.Document) -> str:
    # The same project, version and issue time always give the same UUID
    seed = f"{project['project']['url']}|{release['version']}|{release['issued']}"
    return f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, seed)}"


def _controls(merged: document.Document, minimal: bool) -> document.Document:
    merged = dict(merged)
    if minimal:
        for control_id in document.CONTROL_IDS:
            merged.setdefault(control_id, {"status": "not_assessed"})
    missing = [c for c in document.CONTROL_IDS if c not in merged]
    if missing:
        raise document.InputError(f"no answer in any settings file for: {', '.join(missing)}")
    unknown = sorted(set(merged) - set(document.CONTROL_IDS))
    if unknown:
        raise document.InputError(f"unknown control IDs: {', '.join(unknown)}")
    return {c: merged[c] for c in document.CONTROL_IDS}


def _issuer(project: document.Document) -> document.Document:
    issuer = dict(project["issuer"])
    if "relationship" in issuer:
        issuer["relationship"] = issuer["relationship"].format(
            project=project["project"]["name"], pmc=project.get("pmc", "")
        )
    return issuer


def _local_file(directory: str, uri: str) -> bytes:
    path = pathlib.Path(directory) / uri.rsplit("/", 1)[-1]
    if not path.is_file():
        raise document.InputError(f"missing local file {path} (for {uri})")
    return path.read_bytes()


def _one_year_after(day: datetime.date) -> datetime.date:
    # A decision on 29 February is reviewed by 28 February of the next year
    if (day.month == 2) and (day.day == 29):
        return day.replace(year=day.year + 1, day=28)
    return day.replace(year=day.year + 1)


def _opt_out(project: document.Document, release: document.Document) -> document.Document | None:
    settings = project.get("attestation", {})
    mode = settings.get("mode", "full")
    if mode == "full":
        return None
    if mode != "minimal":
        raise document.InputError(f"attestation mode must be full or minimal, not {mode}")
    missing = [f for f in _OPT_OUT_FIELDS if f not in settings]
    if missing:
        raise document.InputError(f"minimal attestation needs attestation fields: {', '.join(missing)}")
    decided = datetime.date.fromisoformat(settings["decided"])
    review_by = datetime.date.fromisoformat(settings["reviewBy"])
    if review_by > _one_year_after(decided):
        raise document.InputError("attestation reviewBy must be at most 12 months after decided")
    issued = datetime.datetime.fromisoformat(release["issued"]).date()
    if review_by < issued:
        raise document.InputError(f"opt-out lapsed on {review_by}, so the PMC must re-confirm or answer in full")
    return {f: settings[f] for f in _OPT_OUT_FIELDS}


def _release(project: document.Document, release: document.Document) -> document.Document:
    vcs = dict(project["vcs"])
    for key in ("tag", "commit"):
        if key in release:
            vcs[key] = release[key]
    out: document.Document = {"version": release["version"]}
    for key in ("releaseDate", "announcement"):
        if key in release:
            out[key] = release[key]
    out["vcs"] = vcs
    return out


def _sbom(sbom: document.Document, directory: str, keys_uri: str) -> document.Document:
    data = _local_file(directory, sbom["uri"])
    out: document.Document = {"id": sbom["id"], "format": sbom["format"]}
    out.update(_sbom_facts(sbom["format"], data))
    out["uri"] = sbom["uri"]
    out["digests"] = digests.compute(data)
    if "signatureUri" in sbom:
        out["signature"] = _signature_block(directory, sbom["signatureUri"], keys_uri)
    return out


def _sbom_facts(sbom_format: str, data: bytes) -> document.Document:
    parsed = json.loads(data)
    if sbom_format == "CycloneDX":
        return {
            "specVersion": parsed["specVersion"],
            "mediaType": "application/vnd.cyclonedx+json",
            "serialNumber": parsed["serialNumber"],
        }
    if sbom_format != "SPDX":
        raise document.InputError(f"unknown SBOM format {sbom_format}")
    if "spdxVersion" not in parsed:
        return {"specVersion": "3.0", "mediaType": "application/spdx+json"}
    return {
        "specVersion": parsed["spdxVersion"].removeprefix("SPDX-"),
        "mediaType": "application/spdx+json",
        "serialNumber": parsed["documentNamespace"],
    }


def _signature_block(directory: str, uri: str, keys_uri: str) -> document.Document:
    return {
        "format": "openpgp",
        "uri": uri,
        "keyFingerprint": signature.fingerprint(_local_file(directory, uri)),
        "keysUri": keys_uri,
    }
