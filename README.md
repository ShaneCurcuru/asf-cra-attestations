# DRAFT DRAFT DRAFT - DO NOT USE OR REDISTRIBUTE (please)

## ASF CRA attestations

Draft tooling and process for the Apache Software Foundation, acting as an open source software
steward under the EU Cyber Resilience Act, to publish a light-weight Voluntary Security Attestation
(VSA) for every release of every Apache project.

Status: draft for review, 2026-10-15. Nothing here has been agreed with any ASF team or PMC. The
code is a proposal for the ASF Tooling team, who would decide where it lives (working name
`apache/tooling-cra-attestations`).

## The idea in brief

- **One attestation per release.** Each release gets a JSON document that answers the ORC WG Tier 1
  checklist ([template-lite.md](https://github.com/orcwg/cra-attestations/blob/main/proposals/template-lite.md),
  derived from BSI TR-03185-2), bound to the released files by digest and signature.
- **The ASF issues it, the PMC approves it.** The ASF is the issuing steward, the PMC Chair is the
  contact, and the attestation is approved in the same vote as the release and signed by the
  release manager. An optional foundation key can countersign it.
- **Answers come in layers.** An ASF board baseline answers what Foundation policy already
  settles. Optional community baselines (for example, Java projects) come next. Each PMC's
  `project.json` comes last and always wins.
- **Deterministic tools, no AI.** Plain Python that runs on a laptop or a basic ASF instance. The
  same inputs always give byte-identical output, and a missing answer stops generation rather than
  being guessed.
- **ATR is the main caller.** Apache Trusted Releases imports the package as a library at its
  compose, vote and finish steps. The command line stays complete for PMCs releasing outside ATR
  and for testing.
- **Light template only, for now.** Schemas and code read the checklist from the schema file, so a
  heavier Tier 2 template can be added later without reworking the tools.

## Documentation

| Page | What it covers |
| --- | --- |
| [Release attestation process](process/asf-attestation-process.md) | Who issues and signs, how ATR uses the tool, the three data layers, the per-release steps, the optional countersignature and PMC opt-out, roles, and open questions |
| [VSA-lite format](format/README.md) | The JSON format and its design, how a PMC and ATR use the `vsa` package, code conventions, the Commons Lang example, and the issues still to resolve with design |
| [Collector](format/vsa/collect/README.md) | How `vsa-collect` drafts the input files from public ASF data, where each value comes from, swapping data sources, and results on Tomcat, Commons Lang and httpd |
| [Implementation plan](tooling/implementation-plan.md) | Repository layout, data sources, per-control resolvers, and milestones M0 to M5 |
| [Deployment plan outline](deployment/deployment-plan-outline.md) | The areas a rollout across the ASF has to cover: ATR integration and testing, process documents per audience, training and self-testing, adoption, phases, and external docs |
| [Tier 1 tooling survey](tooling/tier1-tooling-survey.md) | Which checklist items public ASF data and ATR can answer, and the approaches compared. Written before the format was packaged, so some file names in it are older |
| [ASF libraries to reuse](tooling/asf-dependencies.md) | Which ASF Tooling and Infra libraries (asfquart, asfpy, asfyaml) and ATR utilities vsa should reuse for UI, integrations and data |

## Python tools

All code is one package, `vsa`, in [format/](format/). It needs Python 3.14 and `jsonschema`; the
`models` extra adds pydantic for ATR.

| Tool | What it does |
| --- | --- |
| [`vsa` command](format/vsa/cli.py) | `generate`, `validate`, `verify` and `intoto` subcommands |
| [`vsa-collect` command](format/vsa/collect/cli.py) | `init` drafts `project.json`; `release` writes `release-X.json` |
| [vsa/assemble.py](format/vsa/assemble.py) | Builds the attestation from the baselines, `project.json`, `release-X.json` and the release files |
| [vsa/document.py](format/vsa/document.py) | Validates a document against the schema |
| [vsa/digests.py](format/vsa/digests.py) | Hashes release files and checks published digests |
| [vsa/signature.py](format/vsa/signature.py) | Reads key fingerprints from OpenPGP `.asc` signatures |
| [vsa/intoto.py](format/vsa/intoto.py) | Wraps an attestation as an in-toto v1 Statement, ready to sign |
| [vsa/typed.py](format/vsa/typed.py) and [vsa/models.py](format/vsa/models.py) | Typed pydantic access for ATR; `models.py` is generated from the schema |
| [vsa/collect/](format/vsa/collect/) | Collector modules: `fetch`, `sources`, `providers`, `records`, `resolve`, `draft` |
| [scripts/models_generate.py](format/scripts/models_generate.py) | Regenerates `vsa/models.py` from the schema, or checks it with `--check` |
| [vsa/schema/vsa-lite.schema.json](format/vsa/schema/vsa-lite.schema.json) | The format itself (JSON Schema draft 2020-12) |

Data and examples: the [ASF baseline](format/baseline/asf.json), an illustrative
[Java community baseline](format/baseline/community/java.json), and the
[Commons Lang 3.17.0 example](format/examples/commons-lang3/) (real artifacts and digests,
illustrative answers).

## Try it

```sh
cd format
uv sync --group test             # or: pip install '.[models]' pytest
vsa validate examples/commons-lang3/commons-lang3-3.17.0.vsa.json
vsa-collect --help
pytest                           # 50 tests, all offline
ruff check . && pyright
```

## Layout

```
README.md          this overview
process/           the release attestation process
tooling/           the tooling survey and implementation plan
deployment/        the deployment plan for rolling the tool out across the ASF
format/            the Python package (vsa and vsa.collect), schema, baselines, examples and tests
```

The Python code follows the
[Apache Trusted Releases code conventions](https://github.com/apache/tooling-trusted-releases/blob/main/atr/docs/code-conventions.md),
so it can move into an ASF repository, or be imported by ATR, without restyling.

## Future: use outside the ASF

We hope to generalize this tool and format later so any open source project or steward can use them for CRA
attestations, not just the ASF. Documentation for projects outside the ASF will come after the ASF rollout. We are
looking for contributors from outside the ASF: if your project or foundation needs CRA attestations too, we would like
to hear from you.

## Licence

Apache License 2.0; see [LICENSE](LICENSE).
