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

import pytest

import vsa.document as document
import vsa.settings as settings

_ROOT = {
    "name": "org",
    "required": ["/issuer", "/controls/VM.01/status"],
    "issuer": {"name": "Org", "website": "https://example.org/"},
    "controls": {"VM.01": {"status": "met", "contact": "mailto:security@example.org"}},
}


def test_chain_finds_parent_in_include_directory(tmp_path: pathlib.Path) -> None:
    shared, project = tmp_path / "shared", tmp_path / "project"
    shared.mkdir()
    project.mkdir()
    _write(shared / "org.json", _ROOT)
    _write(project / "group.json", {"parent": "org.json"})
    _write(project / "product.json", {"parent": "group.json"})
    with pytest.raises(document.InputError, match=r"org\.json not found"):
        settings.chain(project / "product.json")
    layers = settings.chain(project / "product.json", include=[shared])
    assert [pathlib.Path(layer.source).name for layer in layers] == ["org.json", "group.json", "product.json"]


def test_chain_rejects_loop(tmp_path: pathlib.Path) -> None:
    _write(tmp_path / "a.json", {"parent": "b.json"})
    _write(tmp_path / "b.json", {"parent": "a.json"})
    with pytest.raises(document.InputError, match="loop"):
        settings.chain(tmp_path / "a.json")


def test_merge_allows_unchanged_and_unlocked_values() -> None:
    # Restating a required value is not a change, and a lock on status leaves the rest of VM.01 free
    child = {
        "issuer": {"name": "Org"},
        "controls": {"VM.01": {"status": "met", "contact": "mailto:security@product.example.org"}},
    }
    merged = settings.merge([settings.Layer("org", _ROOT), settings.Layer("product", child)])
    assert merged["issuer"] == _ROOT["issuer"]
    assert merged["controls"]["VM.01"]["contact"] == "mailto:security@product.example.org"
    assert "required" not in merged


def test_merge_is_one_level_deep() -> None:
    child = {"issuer": {"role": "steward"}, "controls": {"GV.01": {"status": "met"}}}
    merged = settings.merge([settings.Layer("org", {"issuer": {"name": "Org"}}), settings.Layer("product", child)])
    assert merged["issuer"] == {"name": "Org", "role": "steward"}
    assert list(merged["controls"]) == ["GV.01"]


def test_merge_without_required_lets_any_layer_change_anything() -> None:
    unlocked = {k: v for k, v in _ROOT.items() if k != "required"}
    child = {"issuer": {"name": "Other"}, "controls": {"VM.01": {"status": "not_met", "explanation": "x"}}}
    merged = settings.merge([settings.Layer("org", unlocked), settings.Layer("product", child)])
    assert merged["issuer"]["name"] == "Other"


def test_merge_reports_every_change_to_a_required_field() -> None:
    group = {"issuer": {"name": "Other"}}
    product = {"controls": {"VM.01": {"status": "not_met", "explanation": "x"}}}
    layers = [settings.Layer("org", _ROOT), settings.Layer("group", group), settings.Layer("product", product)]
    with pytest.raises(document.InputError) as error:
        settings.merge(layers)
    message = str(error.value)
    assert "group changes /issuer, which org requires" in message
    assert "product changes /controls/VM.01/status, which org requires" in message


@pytest.mark.parametrize(
    ("required", "match"),
    [
        (["/controls/QA.07"], "no settings file sets it"),
        (["issuer"], "JSON Pointer"),
        ("/issuer", "list of JSON Pointers"),
    ],
)
def test_merge_rejects_bad_required(required: object, match: str) -> None:
    with pytest.raises(document.InputError, match=match):
        settings.merge([settings.Layer("org", _ROOT | {"required": required})])


def test_merge_lets_a_lower_layer_require_more() -> None:
    group = {"required": ["/issuer/website"]}
    product = {"issuer": {"website": "https://other.example.org/"}}
    layers = [settings.Layer("org", {"issuer": {"website": "https://example.org/"}}), settings.Layer("group", group)]
    with pytest.raises(document.InputError, match="product changes /issuer/website, which group requires"):
        settings.merge([*layers, settings.Layer("product", product)])


def _write(path: pathlib.Path, doc: document.Document) -> None:
    path.write_text(json.dumps(doc), encoding="utf-8")
