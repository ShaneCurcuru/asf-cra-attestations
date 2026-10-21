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
import vsa.collect.cli as cli
import vsa.collect.draft as draft
import vsa.collect.fetch as fetch
import vsa.collect.providers as providers
import vsa.collect.records as records
import vsa.collect.resolve as resolve
import vsa.collect.sources as sources
import vsa.document as document
import vsa.settings as settings

_ROOT: Final = pathlib.Path(__file__).resolve().parent.parent
_FIXTURES: Final = pathlib.Path(__file__).resolve().parent / "fixtures" / "collect"
_CACHE: Final = _FIXTURES / "cache"
_GOLDEN: Final = _FIXTURES / "golden"
_PROJECTS_BASE: Final = "https://raw.githubusercontent.com/apache/comdev-projects/trunk/site/json/foundation/"
_TOMCAT_SRC: Final = "https://downloads.apache.org/tomcat/tomcat-11/v11.0.27/src/"
_TOMCAT_BIN: Final = "https://downloads.apache.org/tomcat/tomcat-11/v11.0.27/bin/"
_LANG_SRC: Final = "https://archive.apache.org/dist/commons/lang/source/"
_LANG_MAVEN: Final = "https://repo1.maven.org/maven2/org/apache/commons/commons-lang3/3.17.0/"
_OFFLINE: Final = ["--cache", str(_CACHE), "--offline"]

# Each case is a recorded command and the golden files it must reproduce byte for byte
_INIT_CASES: Final[dict[str, list[str]]] = {
    "tomcat": ["--ref", "11.0.27", "--version", "11.0.27", "--dist-dir", _TOMCAT_SRC],
    "commons-lang": [
        "--ref",
        "rel/commons-lang-3.17.0",
        "--version",
        "3.17.0",
        "--dist-dir",
        _LANG_SRC,
        "--dist-dir",
        _LANG_MAVEN,
    ],
    "httpd": ["--ref", "2.4.69", "--git-url", "https://github.com/apache/httpd"],
}
_INIT_KEYS: Final[dict[str, str]] = {"tomcat": "tomcat", "commons-lang": "commons-lang", "httpd": "httpd-http_server"}
_RELEASE_CASES: Final[dict[str, list[str]]] = {
    "tomcat": [
        "11.0.27",
        "--issued",
        "2026-10-06T00:00:00Z",
        "--release-date",
        "2026-10-06",
        "--tag",
        "11.0.27",
        "--commit",
        "52f3b364e5882a5dbcfc42cb8313a7c2ae532c64",
        "--dist-dir",
        _TOMCAT_SRC,
        "--dist-dir",
        _TOMCAT_BIN,
    ],
    "commons-lang": [
        "3.17.0",
        "--issued",
        "2026-10-15T00:00:00Z",
        "--release-date",
        "2024-08-29",
        "--tag",
        "rel/commons-lang-3.17.0",
        "--dist-dir",
        _LANG_SRC,
        "--dist-dir",
        _LANG_MAVEN,
    ],
    "httpd": [
        "2.4.69",
        "--issued",
        "2026-10-01T00:00:00Z",
        "--tag",
        "2.4.69",
        "--dist-dir",
        "https://downloads.apache.org/httpd/",
        "--source",
        "httpd-*.tar.*",
    ],
}


class AtrStub:
    def lifecycle(self, project: records.ProjectRecord) -> records.LifecycleRecord | None:
        return records.LifecycleRecord(policy_uri="https://tomcat.apache.org/whichversion.html", source="atr")

    def security(self, project: records.ProjectRecord) -> records.SecurityRecord | None:
        return records.SecurityRecord(contact="security@tomcat.apache.org", policy_uri=None, source="atr")


class RosterToolStub:
    def committee(self, pmc: str) -> records.CommitteeRecord | None:
        return records.CommitteeRecord(
            pmc=pmc, name="Apache Tomcat", chair_name="Roster Tool Chair", member_count=7, source="rostertool"
        )


def test_ancestor_keys_are_tried_from_the_top_down() -> None:
    fetcher = fetch.Fetcher(_CACHE, offline=True)
    assert sources.keys_uri(fetcher, "tomcat", [_TOMCAT_SRC]) == "https://downloads.apache.org/tomcat/tomcat-11/KEYS"


def test_answered_draft_generates_a_valid_attestation(tmp_path: pathlib.Path) -> None:
    project = document.load(_GOLDEN / "tomcat-project.json")
    project["controls"].update(
        {
            "GV.02": {"status": "met", "evidence": [{"uri": "https://tomcat.apache.org/getinvolved.html"}]},
            "QA.01": {"status": "not_met", "explanation": "Test answer."},
            "QA.07": {"status": "not_met", "explanation": "Test answer."},
            "EL.01": {"status": "met", "evidence": [{"uri": "https://tomcat.apache.org/whichversion.html"}]},
        }
    )
    release = _tomcat_source_release(tmp_path)
    layers = [*settings.chain(_ROOT / "baseline" / "asf.json"), settings.Layer("project", project)]
    first = document.dump(assemble.attestation(layers, release, str(tmp_path)))
    second = document.dump(assemble.attestation(layers, release, str(tmp_path)))
    assert first == second
    assert document.check(json.loads(first)) == []


def test_baseline_control_missing_from_given_baselines_needs_answer(tmp_path: pathlib.Path) -> None:
    group_only = ["--parent", "java-group.json", "-I", str(_FIXTURES / "baselines")]
    args = [*_OFFLINE, "init", "tomcat", *_INIT_CASES["tomcat"], "--projects-base", _PROJECTS_BASE, *group_only]
    report_path = tmp_path / "report.json"
    assert cli.main([*args, "-o", str(tmp_path / "project.json"), "--report", str(report_path)]) == 0
    report = document.load(report_path)
    assert report["controls"]["VM.02"]["result"] == resolve.NEEDS_ANSWER
    assert "VM.02" in report["toAnswer"]


def test_parents_are_layered_and_win_over_collected_answers(tmp_path: pathlib.Path) -> None:
    out, report_path = tmp_path / "project.json", tmp_path / "report.json"
    # A group baseline whose own parent is the ASF baseline, next to where the draft is written
    group = document.load(_FIXTURES / "baselines" / "java-group.json")
    group["parent"] = "asf.json"
    (tmp_path / "java-group.json").write_text(document.dump(group), encoding="utf-8")
    parents = ["--parent", "java-group.json", "-I", str(_ROOT / "baseline")]
    args = [*_OFFLINE, "init", "tomcat", *_INIT_CASES["tomcat"], "--projects-base", _PROJECTS_BASE, *parents]
    assert cli.main([*args, "-o", str(out), "--report", str(report_path)]) == 0
    project, report = document.load(out), document.load(report_path)
    assert project["parent"] == "java-group.json"
    for control_id in ("LE.01", "QA.05", "QA.03", "VM.01"):
        assert control_id not in project["controls"]
        assert report["controls"][control_id]["result"] == resolve.BASELINE
    assert report["controls"]["QA.05"]["source"] == "java-group.json"
    assert report["controls"]["QA.03"]["source"] == "asf.json"
    assert "SECURITY.md" in report["controls"]["QA.03"]["note"]
    # The draft's parent chain is the one vsa generate follows
    sources = [pathlib.Path(layer.source).name for layer in settings.chain(out, include=[_ROOT / "baseline"])]
    assert sources == ["asf.json", "java-group.json", "project.json"]


def test_contact_style_role_leaves_out_the_chair_name(tmp_path: pathlib.Path) -> None:
    out = tmp_path / "project.json"
    args = [*_OFFLINE, "init", "tomcat", *_INIT_CASES["tomcat"], "--projects-base", _PROJECTS_BASE]
    assert cli.main([*args, "--contact-style", "role", "-o", str(out)]) == 0
    project = document.load(out)
    assert project["contact"] == {"role": "Vice President, Apache Tomcat", "email": "private@tomcat.apache.org"}
    assert project["attestation"] == {"contactStyle": "role"}


def test_draft_alone_does_not_generate(tmp_path: pathlib.Path) -> None:
    project = document.load(_GOLDEN / "tomcat-project.json")
    layers = [*settings.chain(_ROOT / "baseline" / "asf.json"), settings.Layer("project", project)]
    with pytest.raises(document.InputError, match=r"GV\.02, QA\.01, QA\.07, EL\.01"):
        assemble.attestation(layers, _tomcat_source_release(tmp_path), str(tmp_path))


@pytest.mark.parametrize("name", sorted(_INIT_CASES))
def test_init_matches_golden_files(name: str, tmp_path: pathlib.Path) -> None:
    out, report = tmp_path / "project.json", tmp_path / "report.json"
    args = [*_OFFLINE, "init", _INIT_KEYS[name], *_INIT_CASES[name], "--projects-base", _PROJECTS_BASE]
    assert cli.main([*args, "-o", str(out), "--report", str(report)]) == 0
    assert out.read_text(encoding="utf-8") == (_GOLDEN / f"{name}-project.json").read_text(encoding="utf-8")
    assert report.read_text(encoding="utf-8") == (_GOLDEN / f"{name}-report.json").read_text(encoding="utf-8")


def test_local_ids_leave_out_the_version() -> None:
    url = "https://repo1.maven.org/maven2/x/commons-lang3-3.17.0.jar"
    assert draft.local_id(url, "3.17.0") == "commons-lang3.jar"
    assert draft.local_id("https://downloads.apache.org/x/apache-tomcat-11.0.27-src.tar.gz", "11.0.27") == (
        "apache-tomcat-src.tar.gz"
    )


def test_maven_sources_jar_is_not_official() -> None:
    release = document.load(_GOLDEN / "commons-lang-release.json")
    official = sorted(a["name"] for a in release["artifacts"] if a["official"])
    assert official == ["commons-lang3-3.17.0-src.tar.gz", "commons-lang3-3.17.0-src.zip"]


def test_memory_unsafe_language_needs_an_answer() -> None:
    report = document.load(_GOLDEN / "httpd-report.json")
    assert report["controls"]["QA.05"]["result"] == resolve.NEEDS_ANSWER
    project = document.load(_GOLDEN / "tomcat-project.json")
    assert project["controls"]["QA.05"]["status"] == "not_applicable"


def test_missing_signature_is_an_error(tmp_path: pathlib.Path) -> None:
    cache = _copy_cache(tmp_path)
    listing = '<a href="x-1.0-src.tar.gz">x-1.0-src.tar.gz</a>'
    _put(cache, "https://downloads.apache.org/x/", listing.encode("utf-8"))
    fetcher = fetch.Fetcher(cache, offline=True)
    with pytest.raises(document.InputError, match=r"no \.asc signature"):
        draft.release_draft(fetcher, "1.0", "2026-01-01T00:00:00Z", ("https://downloads.apache.org/x/",), {})


def test_offline_run_without_cache_entry_fails() -> None:
    fetcher = fetch.Fetcher(_CACHE, offline=True)
    with pytest.raises(document.InputError, match="offline"):
        fetcher.get("https://downloads.apache.org/not-cached/")


def test_records_file_rejects_unknown_fields(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "records.json"
    path.write_text(json.dumps({"committee": {"chair": "x"}}), encoding="utf-8")
    fetcher = fetch.Fetcher(_CACHE, offline=True)
    with pytest.raises(document.InputError, match="unknown committee fields: chair"):
        providers.Overlay(providers.default_sources(fetcher, _PROJECTS_BASE), str(path))


def test_records_file_replaces_single_fields(tmp_path: pathlib.Path) -> None:
    out, report_path = tmp_path / "project.json", tmp_path / "report.json"
    overlay = ["--records", str(_FIXTURES / "records" / "tomcat-other-systems.json")]
    args = [*_OFFLINE, "init", "tomcat", *_INIT_CASES["tomcat"], "--projects-base", _PROJECTS_BASE, *overlay]
    assert cli.main([*args, "-o", str(out), "--report", str(report_path)]) == 0
    project, report = document.load(out), document.load(report_path)
    assert project["contact"]["name"] == "Example RosterTool Chair"
    assert project["contact"]["role"] == "Vice President, Apache Tomcat"
    assert report["sources"]["committee"] == "committees.json + tomcat-other-systems.json"
    assert report["sources"]["security"] == "tomcat-other-systems.json"
    assert project["controls"]["QA.03"]["evidence"][0] == {"uri": "https://tomcat.apache.org/security.html"}
    assert project["controls"]["EL.01"]["status"] == "met"
    assert "EL.01" not in report["toAnswer"]


def test_report_records_the_digest_of_each_response(tmp_path: pathlib.Path) -> None:
    # Anyone who can write to the cache can change a response, and the report then shows it
    cache = tmp_path / "cache"
    shutil.copytree(_CACHE, cache)
    keys_url = "https://downloads.apache.org/tomcat/tomcat-11/KEYS"
    fetcher = fetch.Fetcher(cache, offline=True)
    fetcher.record(keys_url, 200, b"replaced")
    report_path = tmp_path / "report.json"
    args = ["--cache", str(cache), "--offline", "init", "tomcat", *_INIT_CASES["tomcat"]]
    assert (
        cli.main(
            [*args, "--projects-base", _PROJECTS_BASE, "-o", str(tmp_path / "p.json"), "--report", str(report_path)]
        )
        == 0
    )
    responses = {r["key"]: r["sha512"] for r in document.load(report_path)["responses"]}
    golden = {r["key"]: r["sha512"] for r in document.load(_GOLDEN / "tomcat-report.json")["responses"]}
    assert set(responses) == set(golden)
    assert [k for k in responses if responses[k] != golden[k]] == [keys_url]


@pytest.mark.parametrize("name", sorted(_RELEASE_CASES))
def test_release_matches_golden_files(name: str, tmp_path: pathlib.Path) -> None:
    out = tmp_path / "release.json"
    assert cli.main([*_OFFLINE, "release", *_RELEASE_CASES[name], "-o", str(out)]) == 0
    assert out.read_text(encoding="utf-8") == (_GOLDEN / f"{name}-release.json").read_text(encoding="utf-8")


def test_release_without_a_source_package_fails() -> None:
    args = [*_OFFLINE, "release", "2.4.69", "--issued", "2026-10-01T00:00:00Z"]
    assert cli.main([*args, "--dist-dir", "https://downloads.apache.org/httpd/"]) == 1


def test_replacement_source_needs_no_rule_changes() -> None:
    fetcher = fetch.Fetcher(_CACHE, offline=True)
    public = providers.default_sources(fetcher, _PROJECTS_BASE)
    data = records.Sources(projects=public.projects, roster=RosterToolStub(), security=AtrStub(), lifecycle=AtrStub())
    options = draft.Options(key="tomcat", ref="11.0.27")
    project, report = draft.project_draft(fetcher, data, options)
    assert project["contact"]["name"] == "Roster Tool Chair"
    assert report["sources"] == {
        "project": "projects.json",
        "committee": "rostertool",
        "security": "atr",
        "lifecycle": "atr",
    }
    assert project["controls"]["EL.01"]["evidence"] == [{"uri": "https://tomcat.apache.org/whichversion.html"}]
    assert project["controls"]["QA.06"]["evidence"][0]["description"] == "PMC of 7 members."


def test_version_match_is_exact() -> None:
    assert draft.has_version("https://x/a-1.2.3-src.tar.gz", "1.2.3")
    assert not draft.has_version("https://x/a-1.2.30-src.tar.gz", "1.2.3")
    assert not draft.has_version("https://x/a-11.2.3-src.tar.gz", "1.2.3")
    assert not draft.has_version("https://x/a-1.2.3.1-src.tar.gz", "1.2.3")


def _copy_cache(tmp_path: pathlib.Path) -> pathlib.Path:
    cache = tmp_path / "cache"
    cache.mkdir()
    for path in _CACHE.iterdir():
        (cache / path.name).write_bytes(path.read_bytes())
    return cache


def _put(cache: pathlib.Path, url: str, body: bytes) -> None:
    fetcher = fetch.Fetcher(cache, offline=False)
    fetcher.record(url, 200, body)


def _tomcat_source_release(directory: pathlib.Path) -> document.Document:
    # Stand-in archives with the real detached signatures, which is all generate reads from them
    fetcher = fetch.Fetcher(_CACHE, offline=True)
    release = draft.release_draft(fetcher, "11.0.27", "2026-10-06T00:00:00Z", (_TOMCAT_SRC,), {"tag": "11.0.27"})
    for artifact in release["artifacts"]:
        name = artifact["name"]
        (directory / name).write_bytes(name.encode("utf-8"))
        signature = _ROOT / "tests" / "testdata" / f"{name}.asc"
        (directory / f"{name}.asc").write_bytes(signature.read_bytes())
    return release
