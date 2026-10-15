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
"""Rule-based answers for each checklist control, from collected facts.

Each resolver either proposes a control answer with the source it came from, or says that the
PMC must answer. No resolver guesses: a rule either matches documented data or it does not.
"""

import dataclasses
import re
from collections.abc import Callable
from typing import Final

import vsa.collect.records as records
import vsa.collect.sources as sources
import vsa.document as document

BASELINE: Final[str] = "baseline"
COLLECTED: Final[str] = "collected"
NEEDS_ANSWER: Final[str] = "needs answer"

# Languages whose ordinary code cannot corrupt memory; anything else needs a PMC statement
MEMORY_SAFE_LANGUAGES: Final[frozenset[str]] = frozenset(
    {
        "c#",
        "clojure",
        "dart",
        "erlang",
        "go",
        "groovy",
        "haskell",
        "java",
        "javascript",
        "julia",
        "kotlin",
        "node.js",
        "ocaml",
        "perl",
        "php",
        "python",
        "r",
        "ruby",
        "rust",
        "scala",
        "typescript",
    }
)
# DOAP entries that describe data or templates rather than code, and so do not affect QA.05
NON_CODE_LANGUAGES: Final[frozenset[str]] = frozenset({"freemarker", "sql", "svg", "xml"})

BUILD_DOC_RE: Final[re.Pattern[str]] = re.compile(r"(BUILDING|BUILD|INSTALL)(\.(md|txt|adoc|rst))?", re.IGNORECASE)
CHANGE_LOG_RE: Final[re.Pattern[str]] = re.compile(
    r"(CHANGES|CHANGELOG|RELEASE[-_]?NOTES|NEWS)(\.(md|txt|adoc|rst))?", re.IGNORECASE
)
CI_FILE_RE: Final[re.Pattern[str]] = re.compile(
    r"\.github/workflows/[^/]+\.ya?ml|Jenkinsfile|\.travis\.yml|azure-pipelines\.yml|\.gitlab-ci\.yml|\.circleci/config\.yml"
)
CONTRIBUTING_RE: Final[re.Pattern[str]] = re.compile(r"(\.github/)?CONTRIBUTING(\.(md|txt|adoc|rst))?", re.IGNORECASE)
LICENSE_RE: Final[re.Pattern[str]] = re.compile(r"LICENSE(\.(md|txt))?", re.IGNORECASE)
README_RE: Final[re.Pattern[str]] = re.compile(r"README(\.(md|txt|adoc|rst))?", re.IGNORECASE)
SECURITY_RE: Final[re.Pattern[str]] = re.compile(r"(\.github/)?SECURITY(\.(md|txt|adoc|rst))?", re.IGNORECASE)

_ASF_SECURITY_URI: Final[str] = "https://www.apache.org/security/"
_MIN_PMC_SIZE: Final[int] = 3


@dataclasses.dataclass(frozen=True)
class Facts:
    """Everything the resolvers may look at, gathered before any rule runs."""

    project: records.ProjectRecord
    committee: records.CommitteeRecord | None
    security: records.SecurityRecord | None
    lifecycle: records.LifecycleRecord | None
    repo_url: str | None
    ref: str | None
    commit: str | None
    paths: tuple[str, ...]
    sbom_ids: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class Resolution:
    result: str
    source: str
    note: str
    control: document.Document | None = None


def all_controls(facts: Facts) -> dict[str, Resolution]:
    """Run every resolver, in checklist order."""
    return {c: _RESOLVERS[c](facts) for c in document.CONTROL_IDS}


def _baseline(_facts: Facts) -> Resolution:
    return Resolution(BASELINE, "baseline/asf.json", "Answered once for every PMC by ASF policy.")


def _blob(facts: Facts, path: str) -> str:
    return f"{facts.repo_url}/blob/{facts.ref}/{path}"


def _br01(facts: Facts) -> Resolution:
    return _file_control(facts, BUILD_DOC_RE, "No BUILDING or INSTALL file at the top of the repository.")


def _br02(facts: Facts) -> Resolution:
    versions = facts.project.versions
    source = facts.project.source
    if (not versions) or ("" in versions) or (len(set(versions)) != len(versions)):
        return _needs(source, "The project record lists no releases, or lists one version twice.")
    page = sources.https(facts.project.download_page) or f"https://archive.apache.org/dist/{facts.project.pmc}/"
    count = "1 release" if (len(versions) == 1) else f"{len(versions)} releases"
    description = f"{count} listed in {source}, each with a distinct version."
    return _met(source, [{"uri": page, "description": description}])


def _br04(facts: Facts) -> Resolution:
    return _file_control(facts, CHANGE_LOG_RE, "No CHANGES, CHANGELOG, RELEASE-NOTES or NEWS file at the top.")


def _el01(facts: Facts) -> Resolution:
    policy = sources.https(facts.lifecycle.policy_uri) if facts.lifecycle else None
    if (facts.lifecycle is None) or (policy is None):
        return _needs("", "No lifecycle source gave an end-of-life policy; ATR lifecycle (CLE) data can fill this.")
    return _met(facts.lifecycle.source, [{"uri": policy}])


def _file_control(facts: Facts, pattern: re.Pattern[str], missing: str) -> Resolution:
    if facts.repo_url is None:
        return _needs("", "No git repository could be read for this project.")
    path = _first(facts.paths, pattern)
    if path is None:
        return _needs("repository", missing)
    return _met("repository", [{"uri": _blob(facts, path)}])


def _first(paths: tuple[str, ...], pattern: re.Pattern[str]) -> str | None:
    return next((p for p in paths if pattern.fullmatch(p)), None)


def _gv01(facts: Facts) -> Resolution:
    return _file_control(facts, CONTRIBUTING_RE, "No CONTRIBUTING file at the top or in .github/.")


def _gv02(_facts: Facts) -> Resolution:
    return _needs("", "Whether the guideline sets a quality standard is a PMC statement.")


def _gv03(facts: Facts) -> Resolution:
    evidence: list[document.Document] = []
    homepage = sources.https(facts.project.homepage)
    if homepage:
        evidence.append({"uri": homepage})
    readme = _first(facts.paths, README_RE) if facts.repo_url else None
    if readme:
        evidence.append({"uri": _blob(facts, readme)})
    if not evidence:
        return _needs(facts.project.source, "No https homepage and no README found.")
    return _met(f"{facts.project.source} and repository", evidence)


def _le01(facts: Facts) -> Resolution:
    resolution = _file_control(facts, LICENSE_RE, "No LICENSE file at the top of the repository.")
    if (resolution.control is None) or ("asl20" not in (facts.project.license or "")):
        return resolution
    evidence = [{**resolution.control["evidence"][0], "description": "Apache License 2.0"}]
    return _met(resolution.source, evidence)


def _met(source: str, evidence: list[document.Document]) -> Resolution:
    return Resolution(COLLECTED, source, "", {"status": "met", "evidence": evidence})


def _needs(source: str, note: str) -> Resolution:
    return Resolution(NEEDS_ANSWER, source, note)


def _qa01(facts: Facts) -> Resolution:
    if not facts.sbom_ids:
        return _needs("release directories", "No SBOM was found next to the release files.")
    return _met("release directories", [{"ref": facts.sbom_ids[0], "description": "SBOM published with the release."}])


def _qa02(facts: Facts) -> Resolution:
    uris = [u for u in (sources.https(r) for r in facts.project.repositories) if u]
    if facts.repo_url and (facts.repo_url not in uris):
        uris.append(facts.repo_url)
    if not uris:
        return _needs(facts.project.source, "The project record lists no https source repository.")
    return _met(facts.project.source, [{"uri": u} for u in uris])


def _qa03(facts: Facts) -> Resolution:
    evidence: list[document.Document] = []
    used: list[str] = []
    policy = sources.https(facts.security.policy_uri) if facts.security else None
    if facts.security and policy:
        evidence.append({"uri": policy})
        used.append(facts.security.source)
    path = _first(facts.paths, SECURITY_RE) if facts.repo_url else None
    if path is not None:
        evidence.append({"uri": _blob(facts, path)})
        used.append("repository")
    if not evidence:
        return _baseline(facts)
    return _met(" and ".join(used), [*evidence, {"uri": _ASF_SECURITY_URI}])


def _qa04(facts: Facts) -> Resolution:
    found = [p for p in facts.paths if CI_FILE_RE.fullmatch(p)] if facts.repo_url else []
    if not found:
        return _needs("repository", "No CI configuration found (GitHub Actions, Jenkinsfile and others).")
    if any(p.startswith(".github/workflows/") for p in found):
        uri = f"{facts.repo_url}/tree/{facts.ref}/.github/workflows"
    else:
        uri = _blob(facts, found[0])
    description = f"Automated builds and tests are configured in {len(found)} CI file(s)."
    return _met("repository", [{"uri": uri, "description": description}])


def _qa05(facts: Facts) -> Resolution:
    langs = [lang for lang in facts.project.languages if lang.lower() not in NON_CODE_LANGUAGES]
    source = facts.project.source
    if (not langs) or any(lang.lower() not in MEMORY_SAFE_LANGUAGES for lang in langs):
        return _needs(source, f"Languages listed: {', '.join(langs) or 'none'}. The PMC must answer.")
    kind = "a memory-safe language" if (len(langs) == 1) else "memory-safe languages"
    explanation = f"Written in {', '.join(langs)}, {kind}, according to {source}."
    control = {"status": "not_applicable", "explanation": explanation}
    return Resolution(COLLECTED, source, "", control)


def _qa06(facts: Facts) -> Resolution:
    committee = facts.committee
    if (committee is None) or (committee.member_count < _MIN_PMC_SIZE):
        return _needs("roster", "No PMC roster of three or more members was found.")
    uri = f"https://projects.apache.org/committee.html?{committee.pmc}"
    return _met(committee.source, [{"uri": uri, "description": f"PMC of {committee.member_count} members."}])


def _qa07(_facts: Facts) -> Resolution:
    return _needs("", "The review model (review-then-commit or commit-then-review) is a PMC statement.")


_RESOLVERS: Final[dict[str, Callable[[Facts], Resolution]]] = {
    "GV.01": _gv01,
    "GV.02": _gv02,
    "GV.03": _gv03,
    "LE.01": _le01,
    "LE.02": _baseline,
    "QA.01": _qa01,
    "QA.02": _qa02,
    "QA.03": _qa03,
    "QA.04": _qa04,
    "QA.05": _qa05,
    "QA.06": _qa06,
    "QA.07": _qa07,
    "BR.01": _br01,
    "BR.02": _br02,
    "BR.03": _baseline,
    "BR.04": _br04,
    "VM.01": _baseline,
    "VM.02": _baseline,
    "EL.01": _el01,
}
