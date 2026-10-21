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
import json
import pathlib
import shutil
from typing import Final

import pytest

import vsa.assemble as assemble
import vsa.cli as cli
import vsa.diff as diff
import vsa.digests as digests
import vsa.document as document
import vsa.https as https
import vsa.intoto as intoto
import vsa.keyring as keyring
import vsa.settings as settings
import vsa.verify as verify

_FORMAT: Final = pathlib.Path(__file__).resolve().parent.parent
_PROJECT: Final = _FORMAT / "examples" / "commons-lang3" / "project.json"
_DATA: Final = pathlib.Path(__file__).resolve().parent / "testdata" / "openpgp"
_GOLDEN: Final = _DATA / "hello-1.0.vsa.json"
_ROOT_SHA512: Final = digests.sha512((_FORMAT / "baseline" / "asf.json").read_bytes())


def test_diff_lists_changed_answers_and_the_new_digest(capsys: pytest.CaptureFixture[str]) -> None:
    old = document.load(_GOLDEN)
    new = json.loads(json.dumps(old))
    new["controls"]["QA.07"] = {"status": "met"}
    assert diff.changes(old, old) == []
    assert diff.changes(old, new) == [
        f'controls/QA.07: {json.dumps(old["controls"]["QA.07"], sort_keys=True)} -> {{"status": "met"}}'
    ]
    assert cli.main(["diff", str(_GOLDEN), str(_GOLDEN)]) == 0
    out = capsys.readouterr().out
    assert digests.sha512(_GOLDEN.read_bytes()) in out
    assert "No answers changed." in out


def test_fetch_tries_the_archive_when_downloads_has_moved_on(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[str] = []

    def fake_get(url: str, max_bytes: int = https.MAX_BYTES) -> bytes | None:
        asked.append(url)
        return b"moved" if url.startswith("https://archive.apache.org/") else None

    monkeypatch.setattr(https, "get", fake_get)
    assert verify.fetch("https://downloads.apache.org/commons/hello.txt", None) == b"moved"
    assert asked == [
        "https://downloads.apache.org/commons/hello.txt",
        "https://archive.apache.org/dist/commons/hello.txt",
    ]


def test_generate_checks_signatures_against_keys(tmp_path: pathlib.Path) -> None:
    out = tmp_path / "out.json"
    assert cli.main([*_generate_args(), "--keys", str(_DATA / "KEYS"), "-o", str(out)]) == 0
    assert out.read_bytes() == _GOLDEN.read_bytes()
    assert cli.main([*_generate_args(), "--keys", str(_DATA / "OTHER-KEYS"), "-o", str(out)]) == 1


def test_generate_rejects_a_copied_signature(tmp_path: pathlib.Path) -> None:
    release_dir = _copy_release(tmp_path)
    (release_dir / "hello.txt.asc").write_bytes((_DATA / "hello.txt.outsider.asc").read_bytes())
    layers = settings.chain(_PROJECT)
    release = document.load(_DATA / "release-1.0.json")
    ring = keyring.load((_DATA / "KEYS").read_text(), "KEYS")
    with pytest.raises(document.InputError, match="not in KEYS"):
        assemble.attestation(layers, release, str(release_dir), ring=ring)


def test_inputs_record_every_file_root_first() -> None:
    inputs = document.load(_GOLDEN)["inputs"]
    assert [(i["role"], i["name"]) for i in inputs] == [
        ("settings", "asf.json"),
        ("settings", "java.json"),
        ("settings", "project.json"),
        ("release", "release-1.0.json"),
    ]
    assert inputs[0]["sha512"] == _ROOT_SHA512
    assert inputs[-1]["sha512"] == digests.sha512((_DATA / "release-1.0.json").read_bytes())


def test_intoto_check_rejects_changed_subjects() -> None:
    statement = intoto.wrap(document.load(_GOLDEN))
    assert intoto.check(statement) == []
    statement["subject"][0]["digest"] = {"sha512": "0" * 128}
    assert intoto.check(statement) == ["Statement subjects do not match the attestation's subject.artifacts"]


def test_keyring_checks_subkey_signatures() -> None:
    ring = keyring.load((_DATA / "KEYS").read_text(), "KEYS")
    data = (_DATA / "hello.txt").read_bytes()
    fingerprint = keyring.verify(ring, (_DATA / "hello.txt.asc").read_bytes(), data, "hello")
    assert fingerprint == document.load(_GOLDEN)["subject"]["artifacts"][0]["signature"]["keyFingerprint"]
    with pytest.raises(document.InputError, match="BAD signature"):
        keyring.verify(ring, (_DATA / "hello.txt.asc").read_bytes(), data + b"x", "hello")
    with pytest.raises(document.InputError, match="not in KEYS"):
        keyring.verify(ring, (_DATA / "hello.txt.outsider.asc").read_bytes(), data, "hello")


def test_root_check_rejects_a_shadow_baseline(tmp_path: pathlib.Path) -> None:
    # A project names "asf.json" and puts its own copy, which requires nothing, next to itself
    shadow = document.load(_FORMAT / "baseline" / "asf.json") | {"required": []}
    (tmp_path / "asf.json").write_text(document.dump(shadow))
    project = document.load(_PROJECT) | {"parent": "asf.json"}
    project["controls"]["VM.02"] = {"status": "not_applicable", "explanation": "Changed by the project."}
    (tmp_path / "project.json").write_text(document.dump(project))
    layers = settings.chain(tmp_path / "project.json")
    assert settings.merge(layers)["controls"]["VM.02"]["status"] == "not_applicable"
    with pytest.raises(document.InputError, match="not the expected root"):
        settings.check_root(layers, [_ROOT_SHA512])
    settings.check_root(settings.chain(_PROJECT), [_ROOT_SHA512])


def test_role_contact_style_leaves_out_the_name(tmp_path: pathlib.Path) -> None:
    layers = settings.chain(_PROJECT)
    release = document.load(_DATA / "release-1.0.json")
    layers[-1].doc["attestation"] = {"contactStyle": "role"}
    doc = assemble.attestation(layers, release, str(_DATA))
    assert "name" not in doc["contact"]
    assert document.check(doc) == []
    layers[-1].doc["attestation"] = {"contactStyle": "nickname"}
    with pytest.raises(document.InputError, match="contactStyle"):
        assemble.attestation(layers, release, str(_DATA))


def test_supersedes_itself_and_long_comment_are_rejected() -> None:
    layers = settings.chain(_PROJECT)
    release = document.load(_DATA / "release-1.0.json")
    own_id = document.load(_GOLDEN)["attestationId"]
    with pytest.raises(document.InputError, match="supersede itself"):
        assemble.attestation(layers, release | {"supersedes": [own_id]}, str(_DATA))
    doc = assemble.attestation(layers, release | {"comment": "x" * 501}, str(_DATA))
    assert any(e.startswith("comment:") for e in document.check(doc))


def test_verify_checks_signatures(tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]) -> None:
    keys = ["--keys", str(_DATA / "KEYS")]
    signature = ["--signature", str(_GOLDEN) + ".asc"]
    assert cli.main(["verify", str(_GOLDEN), str(_DATA), *keys, *signature]) == 0
    assert "every signature, including the attestation's own, verifies" in capsys.readouterr().out
    assert cli.main(["verify", str(_GOLDEN), str(_DATA), "--keys", str(_DATA / "OTHER-KEYS")]) == 1
    assert cli.main(["verify", str(_GOLDEN), str(_DATA), *keys, "--signature", str(_DATA / "hello.txt.asc")]) == 1
    tampered = _copy_release(tmp_path)
    (tampered / "hello.txt").write_text("tampered\n")
    assert cli.main(["verify", str(_GOLDEN), str(tampered), *keys]) == 1
    assert "sha512 mismatch" in capsys.readouterr().err
    assert cli.main(["verify", str(_GOLDEN), str(_DATA), "--digests-only"]) == 0
    assert "signatures NOT checked" in capsys.readouterr().out


def test_verify_never_takes_keys_from_an_untrusted_url(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A forger points keysUri at their own site; verify refuses before downloading anything
    forged = document.load(_GOLDEN)
    forged["subject"]["artifacts"][0]["signature"]["keysUri"] = "https://apache-foundation.example/KEYS"
    path = tmp_path / "forged.vsa.json"
    path.write_text(document.dump(forged))
    assert cli.main(["verify", str(path), str(_DATA)]) == 1
    assert "not under a trusted prefix" in capsys.readouterr().err


def _copy_release(tmp_path: pathlib.Path) -> pathlib.Path:
    release_dir = tmp_path / "release"
    shutil.copytree(_DATA, release_dir)
    return release_dir


def _generate_args() -> list[str]:
    release = str(_DATA / "release-1.0.json")
    return ["generate", str(_PROJECT), release, str(_DATA), "--root-sha512", _ROOT_SHA512]
