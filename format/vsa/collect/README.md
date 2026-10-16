# vsa-collect: draft inputs for `vsa generate` from public ASF data

Status: draft, 2026-10-15. Merged into the `vsa` package as `vsa/collect/`; its tests are in `tests/test_collect.py` and `tests/fixtures/collect/`.

`vsa-collect` covers milestones M1 to M3 of [implementation-plan.md](../../../tooling/implementation-plan.md). It reads public ASF data and writes the two input files that `vsa generate` already takes:

- `vsa-collect init KEY` writes a draft **`project.json`**, with every value it could find, plus a report that gives the source of each value and the reason for each gap.
- `vsa-collect release VERSION` writes **`release-VERSION.json`**. That file names every artifact, signature and SBOM for the version in the given download directories.

Controls the collector cannot answer are left out of the draft. That way `vsa generate` refuses to run until the PMC answers them, and the tool never guesses.

## How to run it

```sh
# once per project, then review and commit project.json
vsa-collect --cache cache init tomcat --ref 11.0.27 --version 11.0.27 \
    --dist-dir https://downloads.apache.org/tomcat/tomcat-11/v11.0.27/src/ \
    --parent asf.json -I baseline -o project.json --report report.json

# per release (--issued is the attestation date, normally the vote-pass date; never the clock)
vsa-collect --cache cache release 11.0.27 --issued 2026-10-06T00:00:00Z --tag 11.0.27 \
    --dist-dir https://downloads.apache.org/tomcat/tomcat-11/v11.0.27/src/ -o release-11.0.27.json

vsa generate project.json release-11.0.27.json DIR_WITH_FILES -I baseline -o out.vsa.json
```

`--cache DIR` keeps every network response, including 404s and git file lists. Adding `--offline` repeats a run from the cache alone, with byte-identical output. Without the cache, the output still changes only when the ASF data it reads changes.

Options worth knowing:

- `--parent FILE` names the draft's parent, such as `asf.json` or a community baseline that Java projects agree on, and is written into the draft as its `parent`. It is found the way `vsa generate` will find it: next to the output file, or else in each `-I DIR`. Controls the parent or any of its own parents answers are left out of the draft, even when the collector found something, so that the agreed answer stays in one place. The report says which file answers each control and what the collector found anyway. A control the rules expect from the ASF baseline, but that no parent answers, is listed for the PMC.
- `--git-url` names the GitHub repository when `projects.json` lists none. httpd needs this, because it lists only Subversion.
- `--source 'GLOB'` names the source package when its file name does not say so, for example `httpd-2.4.69.tar.gz`. Without it, `release` fails rather than guessing which file is the official release.
- `--records FILE` (repeatable) replaces single record fields with values from another system. See "Swapping data sources" below.
- `--projects-base` changes where `projects.json` and `committees.json` come from. The default is `https://projects.apache.org/json/foundation/`. The same files are committed to `apache/comdev-projects` under `site/json/foundation/`, which is what I used here, because projects.apache.org is blocked from my sandbox.

## Where each value comes from

| Data | Record | Default source |
| --- | --- | --- |
| Project name, homepage, download page, repositories, languages, licence, release versions | `ProjectRecord` | `projects.json` (built from each project's DOAP file) |
| PMC name, chair, member count | `CommitteeRecord` | `committees.json` |
| Security contact and policy page | `SecurityRecord` | none yet (ATR or a security team attestation later) |
| End-of-life policy page | `LifecycleRecord` | none yet (ATR's lifecycle (CLE) data later) |
| Files at the release tag and the commit ID | | a blobless, shallow `git fetch` of the GitHub mirror (no file contents are downloaded) |
| Artifacts, signatures, SBOMs, KEYS | | Apache directory listings on downloads.apache.org, archive.apache.org or repo1.maven.org |

The rule for each control, and what happens when it doesn't match, follows section 3 of the implementation plan. It is in `vsa/collect/resolve.py`, with every file-name pattern and the memory-safe language list as named constants at the top.

## Swapping data sources

The rules never read a source's own JSON. They read only the four records above, defined in `vsa/collect/records.py`. Each record kind has its own source interface, and `records.Sources` holds one source per kind, so each kind can come from a different system.

- **`vsa/collect/providers.py` is the only code that knows the projects.apache.org schema.** When the ASF RosterTool replaces Whimsy and `committees.json` for people and PMC data, one new class with a `committee(pmc)` method goes in `Sources.roster`. No rule changes. The same goes for an ATR project record (`projects`), a security team attestation (`security`) and ATR lifecycle data (`lifecycle`).
- **ATR, as a library caller,** builds its own `Sources` from its records and calls `draft.project_draft(fetcher, sources, options)`.
- **Without code,** `--records FILE` overlays single fields: for example, the chair from a RosterTool export, while every other committee field still comes from `committees.json`. A kind no source supplies, such as security today, can be given whole in the file. Unknown field names are an error.
- **The report says where each record came from** (`"sources"`), for example `committees.json + rostertool-export.json`. The source of each control answer is in its entry.

`tests/fixtures/collect/records/tomcat-other-systems.json` is a test fixture that stands in for those future systems. It is not real data.

Download listings, KEYS and the git repository are read directly. They are files and repositories, not metadata records, and they have no other planned source. If they gain one, they can move behind the same kind of interface.

## Results on the three test projects

| | Tomcat 11.0.27 | Commons Lang 3.17.0 | httpd 2.4.69 |
| --- | --- | --- | --- |
| Controls collected | 11 | 11 | 8 |
| From the ASF baseline | 4 | 4 | 5 |
| Left for the PMC | GV.02, QA.01, QA.07, EL.01 | GV.02, QA.07, BR.01, EL.01 | GV.01, GV.02, QA.01, QA.05 (C), QA.07, EL.01 |
| Contact, VCS, KEYS found | yes | yes | yes |

For Tomcat, I downloaded the real source packages and signatures, answered the four open controls with test values, and ran `vsa generate`. It produced a valid attestation, byte-identical on two runs. On the unanswered draft, `vsa generate` stops with `no answer in any settings file for: GV.02, QA.01, QA.07, EL.01`.

## Checks

With the collector merged into `format/`, all of the following pass:

- `ruff check` and `ruff format --check`, with the format package's ATR rule set,
- `pyright`,
- ATR's `scripts/interface_order.py` and `scripts/interface_privacy.py`,
- `pytest`: the format package's tests plus 21 collector tests.

The new tests run offline from `tests/fixtures/collect/cache`. Those are real responses recorded on 2026-10-15, trimmed to three projects, top-level files, and placeholder KEYS bodies. They check that each recorded command reproduces the golden files in `tests/fixtures/collect/golden/` byte for byte. They also check layering through parent files, swapping a source for a stand-in RosterTool and ATR, and field overlays, and they cover the failure cases: a missing signature, no identifiable source package, a missing cache entry when offline, and a draft that `vsa generate` must refuse.

## Notes for the format work

- **The example tag looks wrong.** `examples/commons-lang3/release-3.17.0.json` uses `rel/commons-lang3-3.17.0`. The tag on the Commons Lang repository is `rel/commons-lang-3.17.0` (from `git ls-remote --tags`). The release commit is `29ccc7665f3bc5d84155a3092ab2209a053324e6`.
- **QA.01 is per release, but it lives in `project.json`.** The collector makes SBOM IDs leave out the version, for example `commons-lang3-cyclonedx.json`, so a `QA.01` reference written once stays valid across releases. A release with no SBOM would still fail validation against a `met` answer. It may be better for the release file to carry QA.01.
- **The contact defaults to the PMC chair**, following the process draft, with `private@PMC.apache.org` as email.

## Known limits

- **EL.01 is filled only when a lifecycle source gives a policy page.** No public source does yet; ATR's lifecycle (CLE) data is milestone M4.
- **SBOM discovery covers only the directories given.** Commons Lang's SBOMs are found only because the Maven Central directory is passed with `--dist-dir`.
- **BR.02** checks that the project record's release list is non-empty and has no duplicate versions. It does not check ordering.
- **QA.04** treats CI configuration as the repeatable test procedure. The PMC should confirm that during review.
