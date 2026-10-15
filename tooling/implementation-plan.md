# CRA attestation tool: implementation plan

Status: approved by Shane, 2026-10-15. M1 to M3 (the collector) are drafted in [format/vsa/collect/](../format/vsa/collect/README.md). Nothing has been sent outside this project.

This plan turns three earlier drafts into build steps:

- the data mapping in [tier1-tooling-survey.md](tier1-tooling-survey.md),
- the format, generator and validator in [format/](../format/README.md) (the `vsa` package),
- the process and architecture in [asf-attestation-process.md](../process/asf-attestation-process.md), section 2.

The decisions it builds on are already made. The tool gets its own repository, owned by the ASF Tooling team, and ATR is its main caller. PMCs can run it themselves. It is deterministic Python with no AI, and it follows ATR's code conventions.

## 1. Repository layout

The format work has already laid out [format/](../format/README.md) as the repository: `apache/tooling-cra-attestations` (working name), with a `vsa` package at the root, `baseline/`, `examples/`, `tests/` and a `pyproject.toml` that already uses ATR's ruff, pyright and pytest settings and targets Python 3.13+. This plan adds to that layout rather than creating a second one. New parts are marked `+`:

```
pyproject.toml            existing; add pre-commit config copied from ATR
baseline/asf.json         existing
examples/                 existing
vsa/
  assemble.py ...         existing generator, digests, signature, intoto, document, cli
  schema/                 existing vsa-lite.schema.json
+ models.py               pydantic models for baseline, project, release (JSON Schema stays the contract)
+ collect/
+   sources/              one module per data source: atr, whimsy, doap, dist, repo
+   resolvers/            one module per checklist section: gv, le, qa, br, vm, el
+   init.py               writes draft project.json
+   release.py            writes release-X.json
+ render.py               Markdown copy of the ORC WG template
  cli.py                  existing; add init, check-project, release, report
tests/
+ fixtures/               frozen copies of Whimsy, DOAP, dist and ATR data for named projects
+ golden/                 expected outputs, compared byte for byte
```

Anything this plan builds goes into the one `vsa` package in `format/`, so there is only ever one copy of the package.

## 2. Sources

Every source module has two modes: fetch live, or read a frozen copy from a directory. The resolvers only see parsed records, never HTTP. That is what makes the tests and `--offline` reruns exact.

| Module | Reads | Fields used |
| --- | --- | --- |
| `atr` | A pydantic input model that ATR fills in-process. Standalone runs read the catalog's `artifacts.json` and `cle.json` instead. | name, homepage, repositories, security contact, threat model, lifecycle and CLE URL, programming languages, artifacts with signature, checksum and SBOM URLs |
| `whimsy` | `committee-info.json` | display name, site, chair, roster count |
| `doap` | the project's DOAP file, located through `comdev-projects/data/projects.xml` | homepage, repository, programming-language, bug-database |
| `dist` | `downloads.apache.org/<pmc>/` listings and `KEYS`, or `zzz/find-ls2.txt.gz` | artifacts, `.asc`, `.sha512`, KEYS URL |
| `repo` | raw files at the release tag | `SECURITY.md`, `CONTRIBUTING.md`, `README*`, `BUILDING*`, `.asf.yaml`, CI files, lockfiles |

When ATR data is present, it wins over the other sources. Every resolved value records which source it came from.

## 3. Resolvers

Each resolver is a small function. It returns a proposed `status`, its `evidence` URIs, and its source, or it returns "unresolved". It never guesses.

| Control | Resolver rule | If unresolved |
| --- | --- | --- |
| GV.01 | `CONTRIBUTING*` at the repo root or in `.github/` | PMC supplies a link |
| GV.02 | none | PMC answers |
| GV.03 | homepage from ATR or DOAP, plus `README*` | PMC supplies a link |
| LE.01 | baseline answer, plus the `LICENSE` file in the source artifact | none needed |
| LE.02 | baseline answer; the ATR SBOM license result is added as evidence when present | none needed |
| QA.01 | SBOM URL from ATR or dist; otherwise a lockfile found in the repo | PMC states what it cites (process doc, section 8) |
| QA.02 | repositories from ATR or DOAP | PMC supplies a link |
| QA.03, VM.01 | baseline answer, plus ATR's security contact and `SECURITY.md` | baseline only |
| QA.04 | CI files in the repo (`.github/workflows`, `Jenkinsfile`) | PMC supplies a link |
| QA.05 | `not_applicable` when every listed language is on a fixed memory-safe list | PMC answers |
| QA.06 | `met` when the roster count is 3 or more | none needed |
| QA.07 | `.asf.yaml` review rules are listed as evidence only | PMC answers (process doc, section 8) |
| BR.01 | `BUILDING*` or `README*` | PMC supplies a link |
| BR.02 | `met` when versions from ATR or dist are unique and ordered under the project's version scheme | PMC answers |
| BR.03, VM.02 | baseline answer | none needed |
| BR.04 | a URL pattern from `project.json`, filled in with the version | PMC sets the pattern once |
| EL.01 | `met` with the CLE URL when ATR has cycle dates; otherwise the Attic fallback text | PMC answers |

The memory-safe language list and every file-name pattern live in one constants module, so reviewers can see exactly what the tool checks.

## 4. Milestones

Each milestone ends with tests passing, ruff and pyright clean, and golden files reviewed.

1. **M0, conventions and models.** Most of this is already done by the format work. What remains is adding ATR's pre-commit configuration and pydantic models for the input records, with the JSON Schema still the published contract. Done when the existing commons-lang3 example still regenerates byte for byte.
2. **M1, sources with frozen fixtures.** Write the `whimsy`, `doap`, `dist` and `repo` modules, plus frozen fixtures for three contrasting projects: Commons Lang (Java, commit-then-review), Tomcat (Java, a `BUILDING.txt`) and httpd (C, no `.asf.yaml`).
3. **M2, resolvers and `init`.** Write every resolver in section 3. `init` writes a draft `project.json` with unresolved controls left empty, and `check-project` fails until they are answered. Done when the golden drafts exist for all three projects.
4. **M3, `release` and end-to-end generation.** `release` builds `release-X.json` from dist data. Then `generate` produces the VSA-lite JSON, the in-toto statement and the Markdown copy. Done when two runs on the real artifacts give identical output.
5. **M4, ATR adapter (library import, decided 2026-10-15; the command line stays complete for standalone and testing use).** Define the pydantic model ATR fills and an `attest(...)` library call that takes it and returns the documents. The tool does not import ATR. ATR only needs to call the one function. This milestone ships an example of that call and its tests, not a change to ATR.
6. **M5, report and docs.** Write the `report` command and a PMC guide. The docs follow ATR's documentation style: numbered pages with sentence-case headings.

M0 to M3 give a complete standalone tool that any PMC can run. M4 is the integration point for whoever works on ATR.

## 5. Out of scope for this plan

- Signing. The tool holds no keys. ATR already has a sealing module (`atr/sealing.py`, SLH-DSA), which is the natural candidate for the optional countersignature in process doc section 5. That is a question for ATR, not this tool.
- Tier 2 (template-heavy), which is still an empty stub upstream.
- Internal ASF data such as security team records, until process doc open question 3 is settled.

## 6. Questions for Shane

1. The format work's names are `apache/tooling-cra-attestations` for the repository and `vsa` for the package, and this plan now uses them. Are you happy with `vsa` as the package name, given that it will also hold the collector? An alternative is a broader name such as `cra`.
2. Are Commons Lang, Tomcat and httpd the right three test projects? I picked them for their different languages, review models and file layouts.
3. Should I start building the collector (M1 to M3) once you approve? My default is yes, written as new `vsa/collect/` modules. (Done: the collector is now merged into `format/vsa/collect/`.)
