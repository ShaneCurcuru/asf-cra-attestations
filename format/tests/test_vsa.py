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

import copy
import json
import pathlib
from collections.abc import Callable

import pytest

import vsa.assemble as assemble
import vsa.document as document
import vsa.settings as settings
import vsa.signature as signature

_EXAMPLE_DIR = pathlib.Path(__file__).resolve().parent.parent / "examples" / "commons-lang3"
_SIGNATURE_PATH = pathlib.Path(__file__).resolve().parent / "testdata" / "commons-lang3-3.17.0.jar.asc"
_GOOD = document.load(_EXAMPLE_DIR / "commons-lang3-3.17.0.vsa.json")
_MINIMAL = document.load(_EXAMPLE_DIR / "commons-lang3-3.17.0.minimal.vsa.json")

_BROKEN_CASES: dict[str, Callable[[document.Document], object]] = {
    "missing control": lambda d: d["controls"].pop("EL.01"),
    "unexplained not_met": lambda d: d["controls"].update({"QA.07": {"status": "not_met"}}),
    "unexplained partial": lambda d: d["controls"].update({"QA.07": {"status": "partial"}}),
    "met link without evidence": lambda d: d["controls"]["GV.01"].pop("evidence"),
    "VM.01 without contact": lambda d: d["controls"]["VM.01"].pop("contact"),
    "unknown control field": lambda d: d["controls"]["GV.02"].update(foo=1),
    "contact outside VM.01": lambda d: d["controls"]["GV.02"].update(contact="mailto:a@b.c"),
    "md5 digest": lambda d: d["subject"]["artifacts"][0]["digests"].update(md5="0" * 32),
    "openpgp without fingerprint": lambda d: d["subject"]["artifacts"][0]["signature"].pop("keyFingerprint"),
    "dangling sbomRef": lambda d: d["subject"]["artifacts"][1].update(sbomRefs=["nope"]),
    "AU item in controls": lambda d: d["controls"].update({"AU.01": {"status": "met"}}),
    "no official artifact": lambda d: [a.update(official=False) for a in d["subject"]["artifacts"]],
    "not_assessed in full scope": lambda d: d["controls"].update({"GV.01": {"status": "not_assessed"}}),
    "optOut in full scope": lambda d: d.update(optOut=_MINIMAL["optOut"]),
    "minimal scope without optOut": lambda d: d.update(scope="minimal"),
    "missing scope": lambda d: d.pop("scope"),
}


def test_attestation_is_deterministic_and_matches_example(tmp_path: pathlib.Path) -> None:
    release = document.load(_EXAMPLE_DIR / "release-3.17.0.json")
    _write_stand_in_files(release, tmp_path)
    first = document.dump(_generate(release, tmp_path))
    second = document.dump(_generate(release, tmp_path))
    assert first == second
    doc = json.loads(first)
    assert document.check(doc) == []
    for key in ("attestationId", "issuer", "contact", "controls"):
        assert doc[key] == _GOOD[key]


def test_attestation_follows_parents() -> None:
    layers = settings.chain(_EXAMPLE_DIR / "project.json")
    assert [pathlib.Path(layer.source).name for layer in layers] == ["asf.json", "java.json", "project.json"]
    release = document.load(_EXAMPLE_DIR / "release-3.17.0.json")
    # Pointing the project straight at the ASF baseline drops the Java answer for QA.05
    project = layers[-1].doc | {"parent": "../../baseline/asf.json"}
    with pytest.raises(document.InputError, match=r"QA\.05"):
        assemble.attestation([layers[0], settings.Layer("project", project)], release, ".")


def test_attestation_rejects_change_to_required_field() -> None:
    layers = settings.chain(_EXAMPLE_DIR / "project.json")
    release = document.load(_EXAMPLE_DIR / "release-3.17.0.json")
    # A community baseline may not change the issuer, which the ASF baseline requires
    community = settings.Layer("java", layers[1].doc | {"issuer": {"name": "Someone else"}})
    with pytest.raises(document.InputError, match=r"java changes /issuer, which .*asf\.json requires"):
        assemble.attestation([layers[0], community, layers[2]], release, ".")


def test_attestation_from_one_file_without_parent(tmp_path: pathlib.Path) -> None:
    # Another organisation can keep all its settings in one root file, with nothing required
    release = document.load(_EXAMPLE_DIR / "release-3.17.0.json")
    _write_stand_in_files(release, tmp_path)
    root = tmp_path / "root.json"
    root.write_text(document.dump(settings.merge(settings.chain(_EXAMPLE_DIR / "project.json"))))
    assert document.dump(assemble.attestation(settings.chain(root), release, str(tmp_path))) == document.dump(
        _generate(release, tmp_path)
    )


def test_attestation_minimal_marks_unanswered_not_assessed(tmp_path: pathlib.Path) -> None:
    release = document.load(_EXAMPLE_DIR / "release-3.17.0.json")
    _write_stand_in_files(release, tmp_path)
    doc = _generate(release, tmp_path, "project-minimal.json")
    assert document.check(doc) == []
    assert doc["scope"] == "minimal"
    assert doc["controls"]["GV.01"] == {"status": "not_assessed"}
    assert doc["controls"] == _MINIMAL["controls"]


@pytest.mark.parametrize(
    "change",
    [
        {"reviewBy": "2027-09-02"},
        {"decided": "2025-01-01", "reviewBy": "2025-12-31"},
        {"mode": "partial"},
    ],
)
def test_attestation_rejects_bad_opt_out(change: dict[str, str]) -> None:
    layers = settings.chain(_EXAMPLE_DIR / "project-minimal.json")
    layers[-1].doc["attestation"].update(change)
    release = document.load(_EXAMPLE_DIR / "release-3.17.0.json")
    with pytest.raises(document.InputError):
        assemble.attestation(layers, release, ".")


def test_attestation_rejects_missing_answer() -> None:
    layers = settings.chain(_EXAMPLE_DIR / "project.json")
    layers[-1].doc["controls"].pop("EL.01")
    release = document.load(_EXAMPLE_DIR / "release-3.17.0.json")
    with pytest.raises(document.InputError, match=r"EL\.01"):
        assemble.attestation(layers, release, ".")


def test_check_accepts_examples() -> None:
    assert document.check(_GOOD) == []
    assert document.check(_MINIMAL) == []


@pytest.mark.parametrize("name", sorted(_BROKEN_CASES))
def test_check_rejects_broken(name: str) -> None:
    doc = copy.deepcopy(_GOOD)
    _BROKEN_CASES[name](doc)
    assert document.check(doc) != []


def test_fingerprint_reads_issuer() -> None:
    fingerprint = signature.fingerprint(_SIGNATURE_PATH.read_bytes())
    assert fingerprint == "2DB4F1EF0FA761ECC4EA935C86FDC7E2A11262CB"


def _generate(
    release: document.Document, directory: pathlib.Path, project_file: str = "project.json"
) -> document.Document:
    return assemble.attestation(settings.chain(_EXAMPLE_DIR / project_file), release, str(directory))


def _write_stand_in_files(release: document.Document, directory: pathlib.Path) -> None:
    # File facts are computed, so any content works except for SBOMs, which must parse
    sbom = json.dumps({"specVersion": "1.5", "serialNumber": "urn:uuid:dd3f4d4a-567f-3a32-a5a0-7d26a6b05b61"})
    signature = _SIGNATURE_PATH.read_bytes()
    for item in release["artifacts"] + release["sboms"]:
        name = item["uri"].rsplit("/", 1)[-1]
        (directory / name).write_text(sbom if ("format" in item) else name)
        (directory / item["signatureUri"].rsplit("/", 1)[-1]).write_bytes(signature)
