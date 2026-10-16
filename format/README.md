# VSA-lite: machine-readable Tier 1 attestation format (draft 0.3.0)

A JSON Schema for the ORC WG light-weight Voluntary Security Attestation checklist
([`proposals/template-lite.md`](https://github.com/orcwg/cra-attestations/blob/main/proposals/template-lite.md) v0.1,
derived from BSI TR-03185-2), designed so the ASF can issue one per release for every PMC.

Everything here is plain, deterministic Python and JSON: no AI, no service, and no network
access at generation time. It needs Python 3.14 and the `jsonschema` package.

This folder is laid out as a standalone repository for the ASF Tooling team to own. PMCs run its
`vsa` command, and Apache Trusted Releases (ATR) can import it as a library. A name in ATR's
pattern would be `apache/tooling-cra-attestations`.

| File | What it is |
| --- | --- |
| [vsa/schema/vsa-lite.schema.json](vsa/schema/vsa-lite.schema.json) | JSON Schema (draft 2020-12): the format itself, shipped inside the package |
| [baseline/asf.json](baseline/asf.json) | ASF board baseline: issuer, template, and answers set by Foundation policy (LE.02, QA.03, BR.03, VM.01, VM.02). Rarely changes |
| [baseline/community/java.json](baseline/community/java.json) | Illustrative community baseline for JVM-only projects (QA.05). Not agreed by any PMCs yet |
| [examples/commons-lang3/project.json](examples/commons-lang3/project.json) | Per-PMC inputs that rarely change: project, contact, KEYS URL, the remaining answers |
| [examples/commons-lang3/release-3.17.0.json](examples/commons-lang3/release-3.17.0.json) | Per-release inputs: version, tag, issue time, file URLs |
| [examples/commons-lang3/commons-lang3-3.17.0.vsa.json](examples/commons-lang3/commons-lang3-3.17.0.vsa.json) | The generated attestation |
| [examples/commons-lang3/project-minimal.json](examples/commons-lang3/project-minimal.json) | The same project as if its PMC had opted out (illustrative) |
| [examples/commons-lang3/commons-lang3-3.17.0.minimal.vsa.json](examples/commons-lang3/commons-lang3-3.17.0.minimal.vsa.json) | The minimal attestation generated from it |
| [examples/commons-lang3/commons-lang3-3.17.0.intoto.json](examples/commons-lang3/commons-lang3-3.17.0.intoto.json) | Same attestation as an in-toto v1 Statement, ready to sign |
| [vsa/models.py](vsa/models.py) | Pydantic models generated from the schema, for ATR. Do not edit by hand |
| [scripts/models_generate.py](scripts/models_generate.py) | Regenerates `vsa/models.py`, or checks it with `--check` |
| [vsa/collect/](vsa/collect/README.md) | The collector (`vsa-collect`): drafts `project.json` and `release-X.json` from public ASF data |
| [vsa/](vsa/) | Python package: `assemble`, `document`, `digests`, `signature`, `intoto`, and `cli` (the `vsa` command) |
| [tests/test_vsa.py](tests/test_vsa.py) | pytest unit tests |
| [pyproject.toml](pyproject.toml) | Package metadata, the `vsa` entry point, and ruff, pyright and pytest settings |

## Code conventions

All Python here follows the
[Apache Trusted Releases code conventions](https://github.com/apache/tooling-trusted-releases/blob/main/atr/docs/code-conventions.md),
checked against ATR commit `aa7b57f` (2026-10-14):

- **Code style:** ASF license headers, `Final` constants, `_` prefixes for private names, public then
  private functions in alphabetical order, modules imported as `import vsa.x as x`, comments on their
  own lines, no `noqa` or `type: ignore`, and complexity under 10. ATR's
  `scripts/interface_order.py` and `scripts/interface_privacy.py` pass on every file.
- **Tooling:** ATR's ruff rule set and line length (120), pyright, pytest, and the same local
  pre-commit hooks (`.pre-commit-config.yaml`).
- **Python and packaging:** Python 3.14 (`requires-python = "~=3.14.0"`, `.python-version`), managed
  with uv, `dev` and `test` dependency groups, ATR's 5-day dependency cooldown, and `LICENSE` and
  `NOTICE` files.
- **Data models:** ATR validates data with pydantic. Here the JSON Schema stays the single
  definition of the format, because external users of ASF attestations need it to validate them.
  Pydantic models for ATR are generated from it; see "Typed models for ATR" below.

## How ATR would call it

ATR can import the modules directly, in its own import style, with no subprocess:

```python
import vsa.assemble as assemble
import vsa.document as document
import vsa.intoto as intoto

doc = assemble.attestation(baseline, project, release, release_dir, community=[java_baseline])
errors = document.check(doc)
statement = intoto.wrap(doc)
```

Every function is synchronous and only reads local files. `digests.verify` is the one call that
can download, and only when it is not given a local directory.

## Typed models for ATR

The JSON Schema is the definition of the format. For type safety inside ATR, pydantic models are
generated from it:

1. Change `vsa/schema/vsa-lite.schema.json`.
2. Run `uv run --group codegen python scripts/models_generate.py`. It runs a pinned
   `datamodel-code-generator` with fixed options, then ruff, and rewrites `vsa/models.py`. The same
   schema always gives the same file.
3. Commit both. The `models-up-to-date` pre-commit hook and `tests/test_models.py` fail if
   `vsa/models.py` no longer matches the schema.

ATR installs the package with the `models` extra (`vsa-lite[models]`, which adds pydantic) and uses:

```python
import vsa.typed as typed

model = typed.attestation(doc)        # schema check first, then a typed vsa.models.Attestation
model.controls.qa_07.status           # "partial", typed as a Literal
doc = typed.dump(model)               # back to a plain document with the schema's field names
```

Field names are snake_case in Python and keep the schema's names as aliases. `typed.attestation`
always runs the schema check first, because the schema carries rules the generated models don't
enforce, such as `not_assessed` being allowed only in a minimal attestation. Both examples
round-trip through the models unchanged. PMCs who only run the `vsa` command don't need pydantic.

## How a PMC would use it

1. The ASF maintains `baseline/asf.json` once, for everyone.
2. Optionally, a group of similar projects agrees a community baseline in `baseline/community/`.
3. Each PMC keeps a `project.json` (for example in its repo) with its contact and its answers.
4. At release time the release manager writes a short `release-X.json` naming the files, then runs
   `vsa generate` against the directory they already have the signed artifacts in (for example
   their `dist/dev` checkout). The tool hashes every file, reads the key fingerprint out of each
   `.asc`, reads the SBOM serial number, merges the answers, validates the result, and fails if any
   of the 19 controls has no answer.

The same inputs always produce byte-identical output; `attestationId` is a UUIDv5 of project URL,
version and issue time, not a random value.

## Design

**One document per release.** `subject.release.version` is a single version, not a range. A
manufacturer resolving a dependency wants a yes/no answer for the exact file it shipped, and
ASF releases are discrete, PMC-voted events, so a release-time document is the natural unit.
Re-issues use `supersedes`.

**Bound to artifacts by digest.** `subject.artifacts[]` lists each released file with its
`digests` (SHA-256/384/512 or SHA3; MD5 and SHA-1 are rejected, matching ASF release
policy), its detached `signature` (OpenPGP requires the full key fingerprint and the KEYS
URL), and `sbomRefs` pointing at entries in `subject.sboms[]`, which carry their own digest
and signature. A downstream tool that has a file can hash it and find the attestation
without trusting file names. `official: true` marks the PMC-voted source package; Maven jars
and other convenience binaries are `official: false`, mirroring ASF policy.

**AU.01 to AU.03 are structure, not checkboxes.** `issuer` (with `role`: `steward` /
`maintainer` / `third-party`, per the two-tier proposal's "relationship to the project"),
`contact` and `subject` carry them. Everything else is in `controls`, keyed by the template's
IDs.

**Every control must be answered.** All 19 GV/LE/QA/BR/VM/EL items are required, so a gap is
a validation error, not a silent omission. `status` is `met`, `partial`, `not_met` or `not_applicable`;
anything other than `met` needs an `explanation` (this covers the template's "if not,
please explain" lines). Items whose template line asks for a link require at least one
`evidence` entry when met. Evidence can be a URI or a `ref` to an artifact/SBOM in the same
document (QA.01 points at the SBOM this way). VM.01 adds a required `contact` and an
optional `privateReportingUri`.

**Minimal attestations for PMCs that opt out.** Top-level `scope` is `full` or `minimal`. A
minimal attestation must carry `optOut` (`reason`, the PMC's `statement`, `decided`, `decisionRef`
and `reviewBy`), and controls the PMC did not answer have status `not_assessed`, so a
manufacturer's tool can tell "the PMC chose not to attest" from "the practice is missing".
`not_assessed` and `optOut` are rejected in a full attestation. With `attestation.mode: minimal`
in `project.json`, `vsa generate` fills every unanswered control with `not_assessed`, and refuses
to run if `reviewBy` is more than 12 months after `decided` or earlier than the release's issue
date. The process is in section 6 of
[asf-attestation-process.md](../process/asf-attestation-process.md).

**Answers come in layers.** Control answers are merged in three layers, each replacing the
previous one's answer for the same control, whole:

1. **ASF board baseline** (`baseline/asf.json`): set for the whole Foundation, and rarely changes.
   It is the only layer that sets the issuer and template.
2. **Community baselines** (`baseline/community/*.json`, optional, any number, applied in order):
   answers shared by projects with a similar governance style or community conventions, for example
   JVM projects, or C and database projects. Projects opt in with `vsa generate -c FILE`. A community
   baseline may only contain `name`, `description` and `controls`; anything else is rejected.
3. **Project** (`project.json`): the PMC's own answers, which always win.

This is a concept for now. `baseline/community/java.json` only shows the mechanism, using QA.05,
and the Commons Lang example inherits its QA.05 answer from it.

**Built for the light template, ready for a heavy one.** The work targets the Tier 1 light
template. If a Tier 2 heavy template is needed later, it can be added without reworking the tool:
the checklist IDs and schema version are read from the schema file, not repeated in code, so
`vsa generate` and `vsa validate` follow whatever controls a schema requires. A heavy variant would
be a new schema with its own `template.id` and additional control IDs, plus `project.json` answers
for them. The only code that names specific controls is the QA.01 SBOM check and the collector's
per-control resolvers, which a heavy template would extend with new entries.

**Signing is outside the document.** The JSON is the payload. `vsa intoto` wraps it
as an in-toto v1 Statement whose `subject` is the artifact digest list, so the ASF can sign
it with DSSE/Sigstore and log it in Rekor or a SCITT ledger (both named in the two-tier
proposal), or simply publish a detached `.asc` next to it in `dist/`.

## The sample

Artifact names, sizes, SHA-512 digests, signature URLs, key fingerprint and SBOM are the real
published Commons Lang 3.17.0 files. I downloaded them, matched every digest
(`vsa verify`), and checked both OpenPGP signatures against
`downloads.apache.org/commons/KEYS` with `gpg --verify` (good signature, key
`2DB4F1EF0FA761ECC4EA935C86FDC7E2A11262CB`). **The control answers and the contact are
illustrative**; the Commons PMC has not issued this. Evidence links on commons.apache.org and
github.com could not be reached from my sandbox, so those URLs are unverified; the
www.apache.org links resolve. The tag `rel/commons-lang-3.17.0` and its commit `29ccc76` come from the collector's recorded
`git fetch` of the GitHub mirror (an earlier draft used a tag that does not exist).

Two answers deliberately show gaps, and both are real ASF questions: **QA.07** is `partial`
(Commons uses commit-then-review, which arguably falls short of "all changes reviewed by a
non-author") and **EL.01** is `not_met` (no per-version end-of-life policy).

## Run it

```sh
cd format
pip install .        # or: uv sync; add [models] for the pydantic models
vsa generate baseline/asf.json examples/commons-lang3/project.json \
    examples/commons-lang3/release-3.17.0.json DIR_WITH_RELEASE_FILES \
    -c baseline/community/java.json -o out.vsa.json
vsa validate examples/commons-lang3/commons-lang3-3.17.0.vsa.json
vsa verify   examples/commons-lang3/commons-lang3-3.17.0.vsa.json  # downloads ~1.9 MB
vsa intoto   examples/commons-lang3/commons-lang3-3.17.0.vsa.json
pytest
uv run --group codegen python scripts/models_generate.py --check
ruff check . && ruff format --check . && pyright
```

Tested: running `generate` twice on the real release files gave byte-identical output, and its
digests and fingerprints matched the values I had checked by hand. The unit tests pass: the example
and the minimal example validate; 15 broken variants are rejected (among them a missing control,
unexplained `not_met`, MD5 digest, dangling `sbomRefs`, `not_assessed` or `optOut` in a full
attestation, and a minimal one without `optOut`); a missing answer stops generation; and a lapsed,
too-long or unknown opt-out stops generation; and a community baseline is layered in, and is
rejected if it tries to set the issuer. The full suite, including the models tests, passes under
pytest (29 tests). `uv build` produced a wheel that includes the schema, and the installed `vsa`
command validated the example. Python 3.14 is not installed in my sandbox, so the code ran on 3.13 and
pyright type-checked it against 3.14.

## Changes

- **0.3.0:** added the `partial` control status, which needs an `explanation`. The example uses it
  for QA.07, since Commons reviews commits after they land (commit-then-review).
- **0.2.0:** added `scope` (required), `optOut`, and the `not_assessed` control status for the PMC
  opt-out. `not_assessed` controls need no `explanation`; `optOut.statement` covers them.
- **0.1.0:** first draft.

## Issues to resolve with design

1. **Which answers belong in the ASF baseline.** The draft baseline covers LE.02, QA.03, BR.03, VM.01
   and VM.02. Legal and Security would need to agree to own those answers for every PMC. Related:
   which community baselines to define, who agrees and maintains each one, and which answers move
   into them.
2. **Commit-then-review vs. QA.07.** QA.07 asks that every change be reviewed by a non-author, and
   many PMCs use commit-then-review (CTR), where commits are reviewed after they land on commits@.
   Options: count CTR as `met`, answer `not_met`, ask the ORC WG to accept post-commit review, or keep
   `partial`. **For now** the format has a `partial` status and the example answers QA.07 `partial`
   with a CTR explanation. If the decision goes another way, `partial` can stay for other controls
   or be removed in the next schema version.
   *CRA-Expert:* we need a distinct questionnaire we can give to PMCs so they can self-answer 
   to some value that will be accurate enough for this CRA point.
3. **Who Contacts AU.02 later?** Are there any cases where the PMC chair or release manager
   would ever be contacted about past attestations?  If so, how?  Potential recommendations:
   - Make contact.email required, and always a role address (private@project.a.o?).
   - Add ASF contact to AU.01 for authority requests, a role alias owned by VP Legal or VP Security.
   - Keep a stable apache.org page that maps any past attestation to its current chair.
4. **Several products per PMC.** Some PMCs ship products with different languages, dependencies
   or security backgrounds, so one `project.json` per PMC is not enough. A PMC may keep several
   answer files (for example `product1.json`, `product2.json`). To decide: how a release names the
   product file it uses, whether product files can share PMC-wide answers (another layer between the
   community baselines and the product file), and where the files live. *Decided:* CRA answers
   live in these per-PMC files, not in `.asf.yaml` (Shane, 2026-10-16).

## Next tasks

- **Work a non-Java example end to end, to settle which SBOM to cite.** Repeat the Commons Lang
  exercise with a likely non-Java project, such as Apache httpd (C, source-only releases, no SBOM
  published today) or a Python project that ships wheels. Record which SBOM QA.01 should point at
  (source, binary, or none yet), and how QA.05 reads for a non-memory-safe language. The Commons
  Lang example stays as it is until then.

## Open questions

1. **`$id` and `predicateType` are beta apache.org identifiers.** They are
   `https://tooling.apache.org/cra/vsa-lite/0.3.0/vsa-lite.schema.json` and
   `https://tooling.apache.org/cra/vsa-lite/v0.3`, under the Tooling team that will own the repository.
   They are identifiers only. Nothing is served there yet, and the Tooling team should confirm the path
   before a signed attestation leaves beta.
2. **SBOM for source releases.** Commons publishes SBOMs for the jar only. QA.01 is about
   dependencies, so the binary SBOM is likely sufficient, but the WG may want a source SBOM.
