# vsa deployment plan: outline

**Status:** DRAFT outline for review, 2026-10-16. Nothing here has been agreed with any ASF team or PMC.

This outline lists every area a plan to roll out `vsa` across the ASF has to cover: integrating it into Apache Trusted
Releases (ATR), the documents each group of people needs, training and self-testing, the organizational and social
work, and documentation for open source projects outside the ASF. Each section names what it has to produce, who it
is for, and what is still undecided. Once the outline is agreed, each section becomes a page of the full plan.

## 0. Scope and assumptions

These come from decisions already made, and the plan does not reopen them.

- **Tier 1 only.** The plan deploys the VSA-lite template. Tier 2 is out of scope, but nothing in the rollout should
  make it harder to add later.
- **Own repository, ATR as the main caller.** `vsa` lives in its own ASF repository owned by the Tooling team
  (working name `apache/tooling-cra-attestations`). ATR imports it as a library; the `vsa` and `vsa-collect` command
  lines stay complete for standalone releases and testing.
- **Deterministic, no AI.** Every step runs on ATR or a basic ASF cloud instance, gives byte-identical output for the
  same inputs, and fails closed.
- **Reuse what ATR uses.** UI, libraries and conventions follow ATR, as recorded in
  [asf-dependencies.md](../tooling/asf-dependencies.md) (PR #1).
- **Source documents.** The [process](../process/asf-attestation-process.md), the
  [format](../format/README.md), the [collector](../format/vsa/collect/README.md) and the
  [implementation plan](../tooling/implementation-plan.md).

## 1. Audiences and what each one needs

The rest of the plan is organized by deliverable; this table is the index by person. Every row needs a process
document (section 3) and training (section 4).

| Audience | Their job with attestations | Main documents |
| --- | --- | --- |
| Release managers | Review the draft attestation for a release, include it in the vote, sign it | RM guide, ATR walkthrough, CLI quickstart |
| PMC members | Own and review the project profile yearly; approve each attestation in the release vote | PMC guide, profile questionnaire |
| PMC chairs | Named contact (AU.02); confirm the yearly review in board reports; decide on opt-in or opt-out | Chair guide, board report section |
| Incubator PMC and podling mentors | Same as a PMC for podling releases, plus teaching podlings | Incubator addendum |
| Tooling team | Maintain `vsa`, integrate it into ATR, run the countersign step | Maintainer runbook, API reference, release process for `vsa` |
| ATR developers | Call the library at compose, vote and finish; build the pages | Integration guide, API reference |
| Infrastructure | Host the scheduled job for non-ATR releases, hold the countersign key, serve schema URLs | Operations runbook |
| Security team (VP Security) | Own baseline answers for vulnerability handling (QA.03, VM.01, VM.02); link to CRA reporting | Baseline ownership guide |
| Legal (VP Legal) and the Board | Issuer of record; own baseline policy and opt-out policy | Policy summary, baseline change process |
| Auditors, market surveillance authorities, downstream manufacturers | Find, verify and interpret an ASF attestation | Verifier guide, "what an ASF attestation means" |
| Open source projects outside the ASF | Adopt the format and tool for their own releases | External docs (section 7) |

## 2. Tooling integration and testing

### 2.1 Repository and governance of the code

- Move from this draft repository to the Tooling team's repository; agree the name, the package name (`vsa`) and
  committers.
- Contribution guide, code of conduct pointer, `SECURITY.md`, issue tracker, and how changes to the schema are
  reviewed.
- How `vsa` itself is released: an ASF release vote, signed artifacts, PyPI publication if wanted, and an attestation
  for every `vsa` release (the tool attests itself).

### 2.2 Library API for ATR

- The supported public surface: `assemble`, `document`, `typed`, the collector's records and the planned `attest(...)`
  call. Everything else is private.
- Versioning and compatibility policy: semantic versions for the API, separate versions for the schema, and how long
  ATR can stay on an old version.
- Error model: which exceptions mean "PMC must answer something" and which mean a bug, so ATR can show the right
  message to a release manager.
- Data passed in rather than fetched when running inside ATR, so no network calls happen in ATR's request path.

### 2.3 ATR integration points

- Release flow: draft at compose, review before the vote, final document at finish, stored in ATR's `attestable/`
  storage and listed in the release catalog.
- Project settings: where PMCs edit and validate their answers. The open choice between `project.json` and a `cra:`
  block in `.asf.yaml` (asf-dependencies.md) decides this page.
- Data: an ATR provider that reads the `.asf.yaml` `project:` fields ATR already holds (security contact, threat model,
  repositories, lifecycle, version scheme) before any other source.
- UI: ATR pages built the ATR way (asfquart, Jinja2, htpy, Pydantic forms, Bootstrap). `vsa` ships no web app.
- Signing: release manager signatures as today; the optional foundation countersignature through ATR's `sealing.py`
  over `rfc8785` canonical JSON.
- Feature flag or per-project opt-in so ATR can enable attestations for pilot projects first.

### 2.4 Command line

- Stable commands, flags, exit codes and output files for `vsa` and `vsa-collect`, documented in `--help` and a CLI
  reference page.
- The non-ATR path: a scheduled job on an ASF instance that collects, generates and publishes for releases made
  outside ATR, and who looks at its failures.

### 2.5 Testing

- Unit and golden-file tests, kept offline; a documented way to refresh fixtures from live data and review the diff.
- Determinism tests: two runs, byte-identical output, on more than one platform.
- Contract tests between `vsa` and ATR, so a change in either side fails in CI before release.
- Schema compatibility tests: old attestations still validate, or a migration note explains why not.
- A wider fixture set: one project per release style (Java, C, Python, podling, source-only, binaries).
- CI on GitHub Actions within ASF's allowed-actions policy, pre-commit with ATR's hooks, `pip-audit`, and ATR's
  dependency cooldown rules.

### 2.6 Documentation of the code

- API reference generated from docstrings, in the same toolchain and style ATR uses for its docs.
- Developer guide: architecture (collect, then generate), data providers and how to swap one per field, adding a
  control resolver, regenerating `models.py`.
- Docs pass the same markdown linters as tooling-docs so they can move to tooling.apache.org unchanged.

### 2.7 Format and identifiers

- Serve the schema and predicate type at the `tooling.apache.org/cra/` URLs before a signed attestation leaves beta.
- Schema change process: who approves, how the version moves, how ATR and the scheduled job pick it up.
- Alignment with the ORC WG template as it changes upstream.

### 2.8 Operations and support

- What a release manager does when generation fails closed, and who answers them.
- Correcting a wrong attestation: supersede, never edit; how the catalog shows it.
- Monitoring of the data sources (Whimsy now, RosterTool later, ATR's API) for schema changes.
- Security of the tool: threat model, dependency pinning, and how vulnerabilities in `vsa` are handled.

## 3. Process documents for each user group

Each page says what that group does, when, with which tool, and what to do when something fails. The existing process
document becomes the shared reference these pages link to.

- **Release managers:** the per-release steps in ATR, the same steps with the CLI, reading a draft attestation,
  what the vote email says, signing.
- **PMC members:** building the project profile (start from `vsa-collect init`), answering the controls the tool cannot
  (QA.05, QA.07 and the questionnaire the CRA-Expert note asks for), the yearly review, voting.
- **PMC chairs:** the AU.02 role, the board report section, the opt-in to countersigning and the opt-out to a minimal
  attestation.
- **Incubator:** podling differences (disclaimers, mentors' review) and how graduation carries the profile over.
- **Tooling team:** maintainer runbook, releasing `vsa`, changing the schema, upgrading ATR.
- **Infrastructure:** running the scheduled job, the countersign key, hosting the schema URLs.
- **Security team:** owning the baseline answers, how VM.01 and VM.02 relate to the security process and to CRA
  vulnerability reporting, what internal data (if any) feeds attestations.
- **Legal and the Board:** what the ASF commits to as issuer, baseline approval, opt-out policy, Art. 24 steward duties.
- **Auditors and authorities:** where to find an attestation, how to verify it (`vsa verify`), what each field means
  and does not mean, and whom to contact.
- **Baseline governance:** who owns the ASF baseline and each community baseline, which fields each one marks
  `required` (so no PMC can change them), how changes are proposed and versioned, and how PMCs are told.

## 4. Training and self-testing

### 4.1 Materials per audience

- Release managers: a short walkthrough of an ATR release with an attestation, and a CLI dry run.
- PMC members and chairs: a profile workshop built around the questionnaire, with worked examples (Commons Lang,
  Tomcat, httpd).
- Tooling, ATR and Infra: a code walkthrough and the runbooks.
- Security, Legal and the Board: a briefing on what is attested, who answers what, and the risks.
- Auditors: a one-page verifier guide and a sample attestation to verify.
- Format for all: written pages first (they outlive any session), with optional recorded walkthroughs and talks.

### 4.2 Voluntary self-testing

- **Profile readiness check:** any PMC runs `vsa-collect init` and `check-project` on its own project today, with no
  release and nothing published, and sees which answers are missing.
- **Dry-run attestation:** generate an attestation for a past release and review it, with nothing signed or published.
- **ATR preview:** in ATR, show the draft attestation for a release candidate without making it part of the vote.
- **Readiness report:** a deterministic per-project summary (`vsa report`) so chairs and the Board can see progress.

### 4.3 Schedule

Training is tied to the rollout phases in section 6: pilot PMCs train first, release managers before ATR turns on
attestations for their project, chairs before the first board report that includes the CRA section.

## 5. Organizational and social adoption

- **Decision path:** which decisions need the Tooling team, VP Security, VP Legal or a Board resolution, in what
  order.
- **Communication plan:** Shane proposes the work on dev@tooling.apache.org; later announcements to PMC chairs and
  committers; a board report entry. Every outside contact goes through Shane.
- **The case for PMCs:** what changes for a release manager (ideally one review step), what the PMC promises, why the
  ASF does this as a steward, and the opt-out path.
- **Concerns to answer up front:** volunteer time, personal liability, commit-then-review projects (QA.07), projects
  with no SBOM, binaries, and projects releasing outside ATR.
- **Pilot programme:** choose a few PMCs with different languages and review models; collect feedback; publish what
  changed because of it.
- **Support model:** a mailing list or channel for questions, office hours during rollout, an FAQ that grows from real
  questions.
- **Measures of success:** share of releases with an attestation, time added per release, number of fail-closed stops
  and their causes, PMCs with a current profile.
- **Risks and mitigations:** low adoption, wrong answers attested, data source changes, ATR schedule, upstream
  template changes.

## 6. Rollout phases and timeline

CRA anchor dates: vulnerability reporting obligations apply from 11 September 2026, and the rest of the regulation from
11 December 2027. Phases below need dates set against those.

| Phase | What happens | Exit criteria |
| --- | --- | --- |
| 0. Agree | Shane takes the plan to dev@tooling; repository, owners and baseline owners agreed | Repository exists; baseline owners named |
| 1. Alpha | CLI only; pilot PMCs build profiles and dry-run past releases | Pilot profiles complete; fixtures cover pilot projects |
| 2. ATR preview | ATR shows draft attestations for pilot projects; nothing published | Contract tests green; RM feedback addressed |
| 3. Beta | Attestations published for opted-in projects; scheduled job for non-ATR releases | Verifier guide published; schema URLs served |
| 4. General | Attestations expected for every release; opt-out by policy | Board approval; readiness report shows coverage |
| 5. Ongoing | Yearly profile reviews, schema and baseline updates, Tier 2 if wanted | Owned by Tooling team and baseline owners |

## 7. External documentation for any open source project

**Deferred (Shane, 2026-10-16):** these docs are written after the ASF rollout. Until then the repository
[README](../README.md#future-use-outside-the-asf) says we hope to generalize the tool and welcome contributors from
outside the ASF. The list below is what those docs will cover, so that `vsa` could later become a general tool, and
possibly its own top-level project, without rewriting its docs.

- **Generic CRA attestation guide:** what a steward or project attests, how the Tier 1 template maps to practice,
  how to answer each control, independent of the ASF.
- **Split ASF-specific from general:** the core (schema, generator, validator) versus the ASF profile (baselines,
  Whimsy, RosterTool and ATR providers). Docs and code layout show which is which.
- **Adopter guides:** quickstart for a non-ASF project, writing your own baseline, writing a data provider, using it
  from another release system.
- **Format specification:** the schema as a standalone spec with its relationship to the ORC WG template and in-toto.
- **Path to a broader project:** what generalizing needs (neutral naming and identifiers, non-ASF contributors,
  governance), and the ASF route to a top-level project.

## 8. Open questions for the full plan

1. Where do PMCs author CRA answers: `project.json` or a `cra:` block in `.asf.yaml`? Default for now: `project.json`.
2. Which phase dates should the plan commit to against the CRA dates?
3. Which PMCs should pilot? Default: Commons, Tomcat and httpd, matching the test fixtures.
4. Should `vsa` releases be published to PyPI, or only installed by ATR from the ASF release?
