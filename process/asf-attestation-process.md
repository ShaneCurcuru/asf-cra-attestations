# ASF Release Attestation Process (Draft)

**Status:** Draft for discussion, v0.3, 2026-10-15. v0.2 added the automation constraints; v0.3 places the tooling in its own Tooling team repository, called from Apache Trusted Releases (ATR), and adds an optional foundation countersignature (section 5) and an opt-out with a minimal, fully automatic attestation (section 6).
**Scope:** How every Apache PMC (and Incubator podling) produces a light-weight voluntary security attestation (VSA) for each software release, with The Apache Software Foundation acting as the open source software steward under CRA Article 24.

**Sources used:**
- ORC WG light-weight template: `orcwg-cra-attestations/proposals/template-lite.md` (v0.1)
- ORC WG two-tier proposal: `orcwg-cra-attestations/proposals/gen-two-tier-approach.md` (v0.2)
- ORC WG steward FAQ: `orcwg-cra-hub/faq/stewards/` (what-is-a-steward, obligations, whose-codebase, manufacturer-vs-steward)
- `asf-cra-research/README.md` (ASF data sources: Whimsy public JSON, projects.apache.org JSON)
- Project drafts: the VSA-lite format and generator in [format/](../format/README.md), and the [tooling survey](../tooling/tier1-tooling-survey.md) (which read the ATR source)

Per the research README, CRA legal interpretation is out of scope; this process only aims to fill in the ORC WG template reliably for every release. Statements below about existing ASF policy are from general knowledge of ASF practice and should be checked against the current policy pages before this is adopted. Statements about ATR come from the tooling survey's reading of the ATR source, not from running ATR.

---

## 1. Decision: who signs

**The ASF is the issuing entity on every attestation. The PMC prepares and approves it, the PMC Chair is the named contact, and the release manager signs it with the same key used for the release. PMCs that opt in also get a foundation-key countersignature (section 5).**

| Template field | Filled with | Why |
| --- | --- | --- |
| AU.01 Issuing entity | The Apache Software Foundation (legal name, registered address, apache.org) | Only a legal person can be a steward (CRA Art. 3(14)). PMCs are committees of the ASF board, not legal entities, so they cannot be the issuer. The FAQ (`whose-codebase.md`) confirms a foundation can steward the projects it hosts. |
| AU.02 Contact and role | The PMC Chair, as "Vice President, Apache *Project*" | PMC Chairs are officers of the corporation, so the contact speaks for the ASF while still being the person closest to the project. A role alias (private@*project*.apache.org) is listed alongside, so the attestation survives a chair change. |
| Approval | The PMC, in the same vote that approves the release | ASF releases are already acts of the Foundation approved by a PMC vote. Folding the attestation into that vote adds no new governance step, and matches the ORC WG view that maintainers are the most reliable party to attest (two-tier proposal, "Regarding Maintainers"). |
| Signature | Release manager's OpenPGP key from the project `KEYS` file, plus a SHA-512 checksum | This is the same trust chain users already verify for the release artifacts, so no new key infrastructure is needed to start. |
| Countersignature (optional) | A single ASF release-attestation key, applied by ATR | Lets consumers verify "issued by the ASF" with one key instead of hundreds of release manager keys. See section 5. |

**Alternatives considered:**
- *Each PMC as issuer.* Rejected: a PMC has no legal personality, so the attestation would not come from a steward at all.
- *Central ASF staff (e.g. Security or Legal) signs every attestation.* Rejected: there are hundreds of releases a year and the staff would be attesting to facts only the PMC knows. The two-tier proposal also notes that when a steward attests, it is the maintainers who must make the practices true.
- *Foundation key only, no release manager signature.* Rejected: it would break the existing `KEYS`-based verification users already rely on, and would make every release depend on one key and one service.

---

## 2. Tooling and ATR integration

**Where it lives.** All attestation logic is one standalone Python package in its own ASF repository, owned and maintained by the ASF Tooling team (working name `apache/tooling-cra-attestations`; placeholder). It brings together the input collector proposed in the tooling survey (`asf-cra-collect`) and the generator, schema and validator drafted by the format work (the `vsa` package and `vsa/schema/vsa-lite.schema.json` in [format/](../format/README.md)). PMCs use it; they do not own or fork it.

**How ATR uses it.** ATR imports the package as a library and calls it at steps of the release flow it already runs. ATR already stores most of the inputs (security contact, source repositories, lifecycle and end-of-life dates as ECMA-428 CLE documents, signature and checksum checks, SBOM checks, and an `artifacts.json` per release), so ATR passes those in directly and the package does not call ATR's web API. ATR keeps the generated files in its immutable `attestable/` storage, which its docs say is intended for attestation files, and lists them in the release catalog. The package also ships a command-line interface so a PMC member can preview or check an attestation locally, and so releases still made outside ATR can be handled by a scheduled job on an ASF instance.

**Two stages, kept apart.**
1. *Collect* gathers inputs and may use the network (ATR data, Whimsy JSON, DOAP, dist files). It writes plain JSON input files in the format work's model: `baseline/asf.json` (ASF-wide answers), `project.json` (per PMC) and `release-X.json` (per release).
2. *Generate* reads only those files plus the local release artifacts, with no network, and writes the attestation as VSA-lite JSON, a rendered Markdown copy of the ORC WG template, and an in-toto statement ready for signing.

**Rules every step follows.**
- **No AI, basic infrastructure.** Every step is ordinary Python that runs inside ATR or on a basic ASF cloud instance.
- **Deterministic.** The same inputs always produce byte-identical outputs. No value comes from the system clock (the attestation date is the vote-pass date), keys and lists are emitted in a fixed order, and the attestation records the digests of the input files it used. The collected input files are the audit trail for where each answer came from.
- **Fails closed.** The tool never guesses an answer. A missing, malformed or out-of-date field stops generation with a message naming the field. Answers that need judgement, such as memory-safety mitigations (QA.05) or the review model (QA.07), are stated by the PMC; the tool only checks that they are present and use an allowed value.
- **No keys in the package.** The package never holds or uses signing keys. Release managers sign with their own keys as today, and the optional countersignature is applied by a separate ATR signing step (section 5).
- **Conventions follow ATR.** Code layout, Python version and dependencies follow ATR's conventions so ATR can import it directly; the tooling survey lists them. Reconciling them with the format draft (which targets Python 3.9+ with `jsonschema`) is open between those two pieces of work.
- **Tested.** Golden-file tests (fixed inputs with checked-in expected outputs) make any change in output visible in review.

**Entry points.**

| Function / command | What it does | Called by |
| --- | --- | --- |
| `init` | Writes a draft `project.json` with every answer it can resolve, leaving the rest empty | ATR project setup, or a PMC member, once per project |
| `check-project` | Validates `project.json` against the schema and the 12-month review rule | ATR on every project-settings change; project CI if kept in the repo |
| `release` | Writes `release-X.json` from ATR's release data (or the dist listing for non-ATR releases) | ATR when a release candidate is composed |
| `generate` | Builds the attestation from the input files and the artifacts | ATR at release-candidate and finish steps; CLI for previews |
| `validate` / `verify` | Checks the attestation against the schema, and its digests and signatures against the files | ATR before the vote and at finish; anyone afterwards |
| `report` | Prints a per-project summary for the quarterly board report | PMC Chair, or ATR's project page |

---

## 3. Three layers of data

Most template answers are the same for every ASF release, or the same for every release of one project. Splitting the template by how often an answer changes keeps per-release work to a few fields that ATR fills from data it already has.

### Layer A: Foundation baseline (maintained once, by ASF Security and Legal)

Stored as `baseline/asf.json` in the tool repository, versioned and released with it.

| Field | Proposed baseline answer | ASF source to cite |
| --- | --- | --- |
| AU.01 | The Apache Software Foundation, registered address, https://www.apache.org/ | Corporate records |
| LE.01 | All releases are Apache License 2.0 source releases | ASF release policy, licensing policy |
| LE.02 | Dependencies limited to Category A/B licenses; Category X prohibited | ASF 3rd-party licensing policy |
| QA.03 / VM.01 | security@apache.org plus the project's own security page; private reporting supported | apache.org/security |
| VM.02 | ASF vulnerability handling process; CVEs published through the ASF CNA | ASF security committers process |
| BR.02 | Every release has a unique version and is approved by PMC vote | ASF release policy |
| BR.03 | Every artifact is signed (OpenPGP) and checksummed; verification instructions published | ASF release distribution policy, `KEYS` files |
| QA.06 | Releases need at least three binding +1 votes from PMC members, so a project always has more than one active participant | ASF release policy |
| EL.01 (project level) | Retired projects move to the Apache Attic with public notice | Attic process |

Each attestation cites the baseline version it relies on instead of repeating it.

### Layer B: Project profile (maintained by each PMC, reviewed yearly)

Stored as `project.json`, either in ATR's project settings or in the project's main repository; the tool can render it as the `COMPLIANCE.md` file the two-tier proposal suggests. "Can be pre-filled from" means `init` copies that value in; the PMC then reviews and confirms it. Fields marked Manual are always written by the PMC.

| Field | What the PMC supplies | Can be pre-filled from |
| --- | --- | --- |
| AU.02 | PMC Chair name, private@ list | Whimsy `committee-info.json` (chair) |
| AU.03 name/URL | Project name and homepage | ATR project metadata, `committee-info.json`, DOAP |
| GV.01, GV.02 | Link to contribution guide and its quality bar | Manual; site-scan may detect |
| GV.03 | Link to user documentation and intended use | ATR or DOAP description and homepage |
| QA.02 | Source repository link | ATR `repositories`, DOAP `repository` |
| QA.03 / VM.01 | Project security page and contact | ATR `security_contact`, Whimsy `site-scan.json` |
| QA.04 | Link to test docs or CI | Manual |
| QA.05 | Memory-safety mitigations, needed only for C, C++ and similar | ATR or DOAP `programming-language` flags when it applies |
| QA.07 | Review model: review-then-commit, or commit-then-review with post-commit review | Manual; varies by PMC and must be stated honestly |
| BR.01 | Build-from-source docs | Manual |
| EL.01 (versions) | Which release lines are supported and how end of support is announced | ATR lifecycle (CLE) dates where the PMC has set them; otherwise Manual |
| Countersignature | Whether the PMC has opted in (section 5) | Manual |
| Attestation mode | `full`, or `minimal` if the PMC has opted out (section 6) | Manual |

Podlings fill the same profile, with the Incubator PMC as approving body and the Incubator disclaimer noted.

### Layer C: Release record (generated per release)

| Field | Value | Filled by |
| --- | --- | --- |
| AU.03 versions/dates | Release version and vote-pass date | ATR release data |
| Source identifier | Git tag and commit ID of the release | ATR release data |
| Artifact fingerprints | SHA-512 of each source and convenience binary artifact | `generate`, computed from the artifact files |
| Signatures | Release manager key fingerprint and `KEYS` URL | `generate`, read from each `.asc` |
| QA.01 | Link to the SBOM or dependency list for this release | ATR SBOM data, or the release manager |
| BR.04 | Link to release notes or changelog | Release manager, in ATR |
| Input versions | Digests of the baseline, profile and release input files | `generate`, recorded automatically |

---

## 4. Per-release process

This follows the ATR release flow; only the steps marked **new** are additions for PMCs.

1. **Compose the release candidate in ATR** as today. ATR runs its signature, checksum, licence and SBOM checks.
2. **(new) Draft attestation.** ATR calls `release` and `generate` and shows the draft next to the candidate. A missing or stale profile answer blocks starting the vote, with a message naming the field.
3. **(new) Vote on it.** The vote email links the draft attestation alongside the artifacts. A binding +1 on the release is also a +1 on the attestation; voters are asked to check that the project-level answers are still true.
4. **Sign.** The release manager signs the attestation with their release key, as for the other artifacts. ATR runs `verify`.
5. **Finish.** When the vote passes, ATR regenerates the attestation with the vote-pass date, stores it in `attestable/`, publishes it next to the release in the dist area, and lists it in the release catalog, which also serves as the foundation-wide index manufacturers search.
6. **(optional) Countersign.** For opted-in PMCs, ATR applies the foundation countersignature (section 5).
7. **(new) Report.** The PMC Chair includes the `report` summary in the quarterly board report: releases shipped with attestations and any profile fields that changed.

If a vulnerability is later found in an attested release, nothing is re-signed: VM.02 is satisfied by the existing CVE process, and the next release's attestation points to the fix.

Releases still made outside ATR follow the same steps with the CLI run by the release manager, and a scheduled job on an ASF instance picks them up from the dist area for the index. They are not countersigned.

---

## 5. Optional: foundation-key countersignature

A PMC can choose to have each attestation countersigned with one ASF key, in addition to the release manager's signature. This is opt-in per PMC and never required to release.

**What the countersignature means.** It states that the ASF, as steward, confirms this attestation came out of its release process: the PMC voted, the release manager's signature is valid, the artifacts match the attested digests, and the attestation is well-formed. It does **not** mean the ASF audited the code or independently checked the PMC's answers. That wording is published with the key so nobody reads more into it.

**What gets signed.** The attestation document only. Because the attestation lists the SHA-512 of every artifact, countersigning it covers the whole release without the ASF signing each artifact. Release artifacts and their release manager signatures are unchanged.

**The key.**
- One dedicated "ASF Release Attestation" key, used for nothing else, separate from any infrastructure or personal key.
- Generated and held by ASF Infra in a hardware security module or cloud key service, so the private key never sits on a disk or laptop. Only ATR's signing step can use it, and no person signs with it by hand.
- Published at a stable apache.org URL and in the baseline, with its fingerprint in the attestation's documentation. A revocation certificate is kept offline by Infra.
- Rotated on a fixed schedule (for example every two years) with overlap, and immediately on suspected compromise.

**When ATR countersigns.** ATR's countersign step runs automatically at Finish and signs only if every check passes. Each check is a yes/no test on data ATR already holds:
1. the PMC has opted in (profile flag set, recorded with the date and a link to the PMC decision);
2. the release vote passed with at least three binding +1 votes, recorded in ATR;
3. the release manager's signature on the attestation verifies against the project's `KEYS` file;
4. every artifact's SHA-512 matches the attestation;
5. the attestation validates against the VSA-lite schema and the project profile passed its 12-month review rule.

If any check fails, ATR skips the countersignature, logs which check failed, and tells the release manager. The release itself still goes ahead with the release manager's signature alone. Skipped countersignatures are listed in the PMC's `report` output.

**Outputs.** A detached OpenPGP signature (`<name>.attestation.json.asf.asc`) published next to the attestation, and optionally a DSSE-signed in-toto statement recorded in a public transparency log (Rekor or SCITT, both named in the two-tier proposal). The attestation is byte-identical whether or not it is countersigned; only the signature file is added. OpenPGP signatures carry their own timestamp, so the signature bytes differ between runs even though the signed input does not.

**Opting in and out.**
- A PMC opts in by its normal decision process and sets the flag in its profile; the PMC Chair notes it in the next board report.
- Opting out takes effect from the next release. Existing countersignatures stay valid.
- Past releases still in the dist area can be countersigned by request, through the same checks, once the PMC has opted in.

**If something goes wrong.**
- *Wrongly countersigned release* (for example the vote is later found invalid): VP Security publishes a withdrawal notice in the release catalog, and ATR marks that attestation as withdrawn. The key is not revoked.
- *Key compromise:* Infra revokes the key with the offline certificate, issues a new key, and ATR re-countersigns every attestation still in the dist area with the new key, using the same checks.

**Who owns it.** VP Security owns the policy and the published wording, ASF Infra owns the key, and the Tooling team owns the ATR signing step. Turning the option on for the foundation needs Board approval, since it is a new statement made in the ASF's name.

---

## 6. Optional: PMC opt-out (minimal attestation)

Some ASF projects have no realistic commercial use, such as research code, teaching tools or small utilities. Their PMCs can opt out of the full attestation. Every release still gets a **minimal attestation** that ATR builds entirely from data it already holds, with no work from the PMC or the Tooling team. The CRA defines a steward around software "intended for commercial activities" (Art. 3(14)); whether an opt-out changes the ASF's steward role for that project is a legal question this process does not answer.

### Opt-out metadata

Six fields in the `attestation` block of `project.json`:

| Field | Value |
| --- | --- |
| `mode` | `full` (default) or `minimal` |
| `reason` | One of `no-commercial-use`, `research-or-experimental`, `winding-down`, `other` |
| `statement` | One or two sentences in the PMC's words, published in every minimal attestation |
| `decided` | Date of the PMC decision |
| `decisionRef` | Link to the PMC decision in the mailing list archive |
| `reviewBy` | Date by which the PMC must re-confirm, at most 12 months after `decided` |

### Process

1. The PMC decides by its normal process (lazy consensus or a vote) on its private or dev list.
2. The PMC Chair sets the six fields in ATR's project settings. ATR's `check-project` confirms they are present and that `reviewBy` is no more than 12 months out.
3. The Chair notes the opt-out, and its reason, in the next board report, so the Board and VP Security can see every opted-out project in one place.
4. Each release then gets a minimal attestation at the same ATR steps as a full one. Nothing is added to the release manager's work or the vote.
5. Before `reviewBy`, the PMC re-confirms by updating `decided` and `reviewBy`. If it lapses, ATR blocks starting the next release vote until the PMC either re-confirms or fills in the full profile. This is the same rule as a stale full profile.
6. The PMC can switch to `full` at any time by answering the remaining profile fields. Minimal attestations cannot be countersigned (section 5).

### What is automatic, and what needs a person

A minimal attestation includes only the first group below. It marks every control in the second group as not assessed, and says the PMC has opted out, linking `decisionRef` and quoting `statement`.

| | Controls | Where the answer comes from |
| --- | --- | --- |
| **Fully automatic** (no one's time) | AU.01 issuer; AU.02 contact (chair from `committee-info.json`, private@ list); AU.03 name, URL, version, date, tag and commit; artifact SHA-512s, signature fingerprints, `KEYS` URL | Baseline, Whimsy, ATR release data, computed from the files |
| | LE.01, LE.02 licensing; VM.02 vulnerability publication; BR.03 signed and checksummed releases; EL.01 at project level (Attic) | Foundation baseline, backed by ATR's licence, signature and checksum checks |
| | QA.02 public source; QA.03 and VM.01 security contact | ATR `repositories` and `security_contact`, falling back to security@apache.org |
| | QA.06 more than one contributor; BR.02 unique, increasing versions | ATR's vote record (three binding +1s) and release history |
| | QA.05 memory safety, when the project uses only memory-safe languages | ATR or DOAP `programming-language`, marked not applicable |
| **Needs a PMC member** (judgement or a project-specific link) | GV.01, GV.02 contribution guide and quality bar; GV.03 intended use; QA.01 SBOM, unless ATR already finds one; QA.04 tests; QA.05 for C, C++ and similar; QA.07 review model; BR.01 build docs; BR.04 changelog URL; EL.01 per-version support | The PMC, once in the profile, then re-confirmed yearly |
| **Needs the Tooling team** | Nothing per project. The team only fixes projects whose DOAP, ATR metadata or dist layout the collector cannot read. | Tool maintenance |

Most of the PMC work is a one-time setup: about six links and four short answers, plus a yearly check. The opt-out exists for PMCs that won't do even that.

### Format change needed

The VSA-lite schema currently allows each control to be `met`, `not_met` or `not_applicable`, and requires all 19 controls. A minimal attestation needs a fourth status, `not_assessed`, and a top-level `scope: "minimal"` marker, so a manufacturer's tool can tell "the PMC chose not to attest" apart from "the practice is missing". That change belongs to the format work.

---

## 7. Roles summary

| Role | Responsibility |
| --- | --- |
| ASF (Board, VP Security, VP Legal) | Owns and versions the foundation baseline; is the issuer of record; handles Art. 24 steward duties such as authority cooperation and ENISA/CSIRT notification; owns the countersignature policy |
| PMC | Maintains the project profile; approves each attestation in the release vote; keeps the attested practices true; decides whether to opt in to countersigning or opt out to a minimal attestation |
| PMC Chair | Named contact (AU.02); confirms the yearly profile review in a board report |
| Release manager | Reviews the draft attestation in ATR, includes it in the vote, and signs it |
| Incubator PMC | Same as a PMC for podling releases |
| ASF Tooling team | Owns the attestation tool repository and its tests; integrates it into ATR; runs the ATR countersign step |
| ASF Infra | Holds the countersignature key; hosts the scheduled job for releases made outside ATR |

---

## 8. Known gaps to resolve before rollout

- **SBOM (QA.01):** the ASF has no foundation-wide SBOM requirement. Until there is one, projects may cite a lockfile or `LICENSE`/`NOTICE` dependency list, and the attestation should say which.
- **Review model (QA.07):** commit-then-review projects cannot truthfully check "all changes reviewed before merge". The attestation should allow stating the actual model rather than leaving the box blank.
- **Version end-of-life (EL.01):** project-level retirement is covered by the Attic. Per-version support periods are only available for PMCs that set lifecycle dates in ATR.
- **Convenience binaries:** the ASF only formally releases source. The attestation should state whether binary fingerprints are in scope or listed for information only.
- **Dependencies:** following the two-tier proposal, ASF attestations should cover only ASF-produced components and say so explicitly for third-party dependencies.

## 9. Open questions

1. Does ATR already have, or plan, a foundation signing key or sealing service that the countersignature should reuse instead of a new key?
2. Should `project.json` live in ATR's project settings (one place, easy to validate) or in each project's repository (visible in the code history)?
3. Which internal ASF data (security team records, CNA data) needs to be exposed to complete VM.01/VM.02 accurately? This is the "internal data" question from the research README.
4. What should the tool repository be called, and is dev@tooling.apache.org the right place to propose it and the ATR integration?
5. Should the Board or VP Security be able to refuse a PMC's opt-out, for example for a project that is widely used commercially, or is the board-report notice enough?
