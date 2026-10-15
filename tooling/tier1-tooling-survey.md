# Tooling survey: automating ASF Tier 1 CRA attestations

Status: draft, revised 2026-10-15 for the standalone-Python constraint. Read-only survey; nothing was changed in any repository.

## Summary

- The ORC WG Tier 1 checklist (`proposals/template-lite.md` in orcwg-cra-attestations) has **22 items**. Using public ASF data and foundation-wide policy, **11 can be filled automatically** for every release, **9 can be auto-detected but need a one-time project confirmation**, and **2 need a human answer** (GV.02 contribution quality standard, QA.07 change review).
- The biggest finding is that **Apache Trusted Releases (ATR)**, the ASF Tooling team's new release platform (beta at releases.apache.org, catalog at release-catalog.apache.org), already stores most of what the checklist asks for: security contact, threat model, source repositories, lifecycle and end-of-life dates (as ECMA-428 CLE documents), signatures, checksums, SBOMs, and a PURL per release. Its storage docs say its immutable `attestable/` directory is meant to "eventually write attestation files".
- **Constraint (from Shane):** any tooling must be independent, reusable Python that the ASF maintains and runs itself on basic ASF cloud instances, deterministic, with no AI at run time, and easy for any PMC to use.
- **Recommendation: a standalone, deterministic Python collector** (working name `asf-cra-collect`) that pre-fills the inputs for the format work's generator, `format/tools/vsa.py`, from public ASF data (Whimsy JSON, DOAP, ATR catalog JSON, dist files, repo files). It writes the draft `project.json` a PMC reviews and commits once, and the `release-X.json` for each release; `vsa.py generate` then builds and validates the attestation exactly as it does today. Any PMC can run both on a laptop or an ASF VM, a cron job can run them for every release, and ATR, which is itself Python, can import them at release time.
- Output format: the format work's VSA-lite JSON (`format/vsa-lite.schema.json`) and its in-toto wrapper, published next to `artifacts.json` and `cle.json` in the release catalog. This survey does not define a separate format or input model.

## Data sources checked

| Source | What it gives | How verified |
| --- | --- | --- |
| Whimsy `committee-info.json` | Per PMC: display name, site, description, chair, roster with join dates, mailing list, report schedule | Schema read from generator source `apache/whimsy` `www/roster/public_committee_info.rb` (whimsy.apache.org is blocked from this sandbox) |
| Whimsy `site-scan.json` | Per project website: pass/fail for links to Security, License, Privacy, etc. | Checks read from `lib/whimsy/sitestandards.rb` |
| Whimsy `download_check` | Checks a download page links every artifact with `.asc` and a hash | `tools/download_check.rb` |
| projects.apache.org / DOAP | homepage, repository, category, programming-language, releases, bug-database | `apache/comdev-projects` `scripts/cronjobs/parseprojects.py`, `data/projects.xml` (331 DOAP locations) |
| downloads.apache.org | Artifacts with `.asc` + `.sha512`, per-project `KEYS`, full listing `zzz/find-ls2.txt.gz` | Fetched live, e.g. tomcat-11 v11.0.27 `bin/` and `KEYS` |
| Project repos on GitHub | `SECURITY.md`, `CONTRIBUTING.md`, `README.md`, `BUILDING.*`, `.asf.yaml`, CI config | Sampled 12 large projects (below) |
| ATR (`apache/tooling-trusted-releases`, HEAD 2026-10-14) | Project metadata and security fields, lifecycle/CLE, SBOM checks with OSV and license analysis, signature/hash/RAT checks, release catalog JSON, PURLs, sealed records | Source and `atr/docs/*` read; live sites blocked from this sandbox |

Sample of repo files (HTTP 200 at repo root on main/master/trunk): SECURITY.md 10 of 12 (Airflow keeps it in `.github/`), CONTRIBUTING.md 10 of 12, `.asf.yaml` 11 of 12 (httpd lacks it). No project used `BUILDING.md`, but Tomcat has `BUILDING.txt`, so detection must try several names and locations.

## Checklist mapping

Levels: **Auto** = filled with no human input. **Detect + confirm** = tool proposes a value, the PMC confirms once and it carries over to later releases. **Human** = needs a PMC statement.

| ID | Item | Source | Level |
| --- | --- | --- | --- |
| AU.01 | Issuing entity, address, website | Foundation constant: The Apache Software Foundation, registered address (take from apache.org/foundation/contact), https://www.apache.org/ | Auto |
| AU.02 | Contact name and role | PMC chair from `committees.json` `chair` (role "Vice President, Apache X"), as the official representative of the PMC (decided by Shane, 2026-10-15) | Auto |
| AU.03 | Project name, URL, version, date | ATR project metadata or DOAP name/homepage; version and release date from ATR or `releases.json`; add SHA-512 per artifact from `artifacts.json` and source commit / SWHID that ATR records, as the two-tier proposal asks | Auto |
| GV.01 | Contribution guideline link | `CONTRIBUTING.md` (root or `.github/`), else project "get involved" page | Detect + confirm |
| GV.02 | Guideline sets a quality standard | No data source; PMC statement | Human |
| GV.03 | Usage / purpose docs link | DOAP or ATR homepage and description, `README.md` | Detect + confirm |
| LE.01 | Everything under an OSS license | ASF release policy requires Apache-2.0; ATR license and RAT checks give per-release evidence; link `LICENSE` in the source artifact | Auto |
| LE.02 | Dependencies under OSS licenses | ASF third-party policy (Category A/B/X, apache.org/legal/resolved.html) applies to all releases; ATR's SBOM license analysis gives evidence where an SBOM is shipped | Detect + confirm |
| QA.01 | Direct dependency list with checksums | SBOM URL from `artifacts.json` when the release ships `*.cdx.json`; otherwise a lockfile/manifest link (`pom.xml`, `package-lock.json`, etc.) | Detect + confirm; largest gap today |
| QA.02 | Public source with history | ATR `repositories`, DOAP `repository`, gitbox/GitHub | Auto |
| QA.03 | How to report a vulnerability | ATR `security_contact`, `SECURITY.md`, site-scan "security" link, fallback https://www.apache.org/security/ | Auto |
| QA.04 | Repeatable tests | Detect CI (`.github/workflows`, `Jenkinsfile`, ci-builds.apache.org jobs); PMC confirms link | Detect + confirm |
| QA.05 | Memory-safety mitigations | DOAP/ATR `programming-language`: if only memory-safe languages, mark not applicable automatically; C/C++ projects need a statement | Detect + confirm |
| QA.06 | More than one active contributor | PMC roster size from `committee-info.json` (board requires 3+ PMC members); release vote needs 3 binding +1s | Auto |
| QA.07 | All changes reviewed by a non-author | ASF projects choose CTR or RTC; `.asf.yaml` branch protection (`required_pull_request_reviews`) is partial evidence only | Human |
| BR.01 | Build-from-source docs | `BUILDING.*`, `README.md`, website | Detect + confirm |
| BR.02 | Unique, increasing versions | ATR version scheme (semver/calver) and release history; checkable mechanically | Auto |
| BR.03 | Integrity verification documented | ASF release policy mandates `.asc` + checksum + `KEYS`; ATR signature/hash checks per release; link https://www.apache.org/info/verification.html | Auto |
| BR.04 | Change log per release | Release notes / `CHANGES` / JIRA release notes; ATR announce email. Needs a per-project URL pattern set once | Detect + confirm |
| VM.01 | Security contact, private reporting | ATR `security_contact` (security@apache.org or the PMC's list), https://www.apache.org/security/ | Auto |
| VM.02 | Publishes vulnerability info | Foundation constant: ASF security process and the ASF as a CVE Numbering Authority (apache.org/security/committers.html) | Auto |
| EL.01 | Discontinuation communicated | ATR lifecycle page and CLE cycle dates (end of support / end of life); Attic process for retired projects as the foundation-wide fallback | Detect + confirm |

What this means in practice: once a PMC has confirmed its 9 "detect + confirm" answers and given its 2 human answers, every later release can produce its attestation with no manual work, because the per-release fields (AU.03, LE.01 evidence, QA.01 SBOM, BR.03 checks) all come from the release itself.

## Tooling approaches compared

| | A. Standalone generator | B. Built into ATR | C. Per-project build plugin / CI action | D. Manual template or form |
| --- | --- | --- | --- | --- |
| Shape | Python script or Whimsy cron that reads public JSON and repo files, writes `COMPLIANCE.md` + JSON per release | ATR emits the attestation at the Finish/announce step, stores it in `attestable/`, publishes it in the release catalog | Maven/Gradle plugin or GitHub Action in each project | PMC fills the template by hand, perhaps through a Whimsy form |
| Covers every release | Yes, by scanning dist | Yes for ATR releases; legacy `svn:dist:release` releases are still catalogued, with fewer fields | Only projects that adopt it | Only if PMCs remember |
| Data quality | Scrapes heterogeneous dist layouts and DOAP; drifts | Uses data ATR already validates and stores | Good for SBOM, weak for governance fields | Varies by PMC |
| Issuer fits steward role | Yes (foundation runs it) | Yes, and ATR can seal it with its own signing key | No: the project, not the foundation, issues it | Yes |
| Work per PMC | None | One-time settings | Build changes in 200+ build systems | Every release |
| Engineering cost | Low to start, ongoing upkeep | Moderate, needs ATR team buy-in | High in aggregate | None |
| Fits "standalone Python, ASF-run, deterministic" | Yes, and pairs with `format/tools/vsa.py` | Partly: ATR is Python, but the logic would be locked inside one service | No | Not tooling |

## Recommendation

Build **a standalone collector that feeds the existing `vsa.py`, in its own repository owned by the ASF Tooling team, with ATR as its main caller** (Shane's decision, 2026-10-15). This combines options A and B: the logic stays in a separate, reusable package that PMCs can run themselves, and ATR calls it or integrates closely with it at release time. The format, schema, generator and validator already exist in [format/](../format/README.md); this tool only gathers their inputs.

1. **Two steps, kept apart.** Step 1, `asf-cra-collect`, needs the network: it reads ASF data and writes plain JSON input files. Step 2, `vsa.py generate`, needs no network and turns those files plus the release artifacts into the attestation. Keeping the network out of step 2 is what makes the attestation reproducible; the collected input files are the audit trail for where each answer came from.
2. **Package shape.** A pip-installable package with a CLI and a library API, laid out and tooled like ATR (see "Follow ATR's code conventions" below), with few dependencies beyond those ATR already uses. It lives in its own ASF repository owned by the Tooling team, together with `vsa.py`, with an Apache-2.0 licence and unit tests over fixed fixture data, so the ASF can maintain it with no outside help.
3. **Deterministic, rule-based resolvers.** One small function per control, following the mapping table above, returns the proposed `status`, `evidence` URIs and the source it used. Inputs are fetched once and cached, sorted keys, no heuristics beyond documented file-name and URL checks, and no AI anywhere.
4. **Uses the format work's input model as is.** `baseline/asf.json` (ASF-wide answers), `project.json` (per PMC, committed once), and `release-X.json` (per release). `asf-cra-collect init PROJECT` writes a draft `project.json` with every control it can resolve filled in and the rest left empty, so `vsa.py generate` refuses to run until the PMC answers them. `asf-cra-collect release PROJECT VERSION` writes `release-X.json` from the dist listing or ATR's `artifacts.json`.
5. **ATR first, standalone second.** The main path is ATR calling the tool at the Finish step, reading its own stored data (security contact, lifecycle and CLE, SBOM and signature checks, `artifacts.json`) directly and publishing the attestation in the release catalog. The same package also runs standalone: a PMC's release manager can run it locally before the vote, and a Tooling-run cron job can cover releases still made by committing to `svn:dist:release`. The tool must not require ATR's database, so it takes ATR data through a plain input interface that ATR fills.
6. **Skip C and D** except as fallbacks: C conflicts with the steward being the issuer, and D will not scale across all PMCs.

### Follow ATR's code conventions

Shane's direction is that all Python tooling follows the conventions and style of Apache Trusted Releases (source: `apache/tooling-trusted-releases`, `atr/docs/code-conventions.md`, `code-policies.md`, `pyproject.toml`; Shane's local copy is `~/src/f/tooling-trusted-releases`). For the collector, and for `vsa.py` if it moves into the same package, that means:

- **Toolchain:** `uv` for dependencies, `pyproject.toml`, `ruff` with line length 120 and ATR's rule set (including `C90` complexity, `S` bandit, `I` isort, `N` naming, `UP`), `pyright`, `pytest`, and the same pre-commit hooks.
- **Python version:** ATR requires Python `~=3.14.0`. That conflicts with `vsa.py`'s Python 3.9+ target (see open questions).
- **Imports:** `import atr.models.sql as sql` style. Import modules by their last name part and never import names from modules.
- **Typing and constants:** typed throughout, `Final` on every UPPERCASE module constant, `global_` prefix for globals, and a single leading underscore for private names.
- **Structure:** small focused modules, no nested functions, functions sorted alphabetically, cyclomatic complexity under 10, early returns, no lint or type-checker ignore comments, double quotes, f-strings, and explicit checks instead of `assert`.
- **Models:** ATR describes its JSON records with strict pydantic models (`atr/models/schema.py`), where `vsa.py` uses a JSON Schema file and `jsonschema`. The collector's input and output records would follow the pydantic pattern so ATR can import them directly.

### Differences from the format work to settle

- **Per-project file format.** I had proposed a `cra-attestation.toml`; that is dropped in favour of the format work's `project.json`.
- **What belongs in the ASF baseline.** `baseline/asf.json` covers LE.02, QA.03, BR.03, VM.01 and VM.02. This survey's mapping would also treat **LE.01** (ASF release policy requires Apache-2.0) as foundation-wide, and fill **QA.06** (PMC roster size) and **BR.02** (version history) from data rather than a PMC answer. These fit the existing model: the collector writes them into `project.json`.
- **EL.01.** The format example marks it `not_met` (no per-version end-of-life policy). Projects that set cycle dates in ATR already publish end-of-life data as ECMA-428 CLE documents, so the collector can mark EL.01 `met` with the CLE URL as evidence for those projects, and the Attic process could be a foundation-wide fallback for whole-project retirement.
- **Network at verify time.** `vsa.py verify` downloads artifacts, which is fine because it is a check, not generation.

## Open questions for Shane

All questions go to Shane only. Once Shane approves a plan, Shane will publish it in their own repository and coordinate any ASF work on dev@tooling.apache.org. The build plan is in [implementation-plan.md](implementation-plan.md).

1. Decided (2026-10-15): AU.02 names the PMC chair, as the official representative of the PMC, with the ASF as issuer. Still open, and marked as a TODO in the collector code: should a PMC ever be able to name the release manager instead, as the person who ran the build?
2. Commit-then-review vs. QA.07 is now tracked in one place: "Issues to resolve with design" in [format/README.md](../format/README.md#issues-to-resolve-with-design). For now the format answers QA.07 `partial` with an explanation. The collector leaves QA.07 for the PMC to answer either way.
3. Decided (2026-10-15): the tool gets its own repository owned by the Tooling team. ATR imports it as a Python library, and the tool keeps full command line options for standalone and testing use.
4. Decided (2026-10-15): baselines are layered. The ASF baseline is set by the board for the whole organization and rarely changes. Optional community baselines sit on top of it, shared by projects with similar governance or conventions, such as Java projects, or C and database projects. The project file comes last. The format work is adding the layering to `vsa generate`, and the collector takes the same layers with `--baseline`. Still open: whether LE.01 joins the ASF baseline. My default is yes, because ASF release policy requires Apache-2.0 for every release. QA.06 and BR.02 stay computed by the collector unless a baseline answers them.
5. Decided (2026-10-15): all Python tooling follows ATR conventions, `vsa` included. The question was: should `vsa.py` move to ATR's conventions too? That would mean Python 3.14 instead of 3.9+, pydantic models alongside or instead of the JSON Schema, and a package instead of one file. My default is to keep the JSON Schema as the published format, write the collector to ATR's conventions, and port `vsa.py` into the same package later. The format work owns that file, so it's their call to make with you.

## Limits of this survey

whimsy.apache.org, projects.apache.org, releases.apache.org and release-catalog.apache.org were blocked from the sandbox, so their field names come from the generator source code, not live files. The repo-file sample covers 12 large projects and likely overstates coverage across all PMCs. CRA legal interpretation is out of scope, per the research README.
