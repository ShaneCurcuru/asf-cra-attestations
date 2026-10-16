# ASF-maintained libraries for the vsa tool

**Status:** DRAFT review, 2026-10-16. Reviewed at the `main` heads of the repositories below on that date.

When `vsa` (and `vsa-collect`) needs a UI, a new integration, or a new kind of data, it should reuse what the ASF
Tooling and Infrastructure teams already maintain, in the way ATR already uses it. This page records what exists, what
ATR does with it, and what that means for us.

## Summary: rules for building on vsa

1. **Follow ATR, not just Infra.** ATR is our main caller and its choices are the precedent. Where ATR deliberately
   declined an Infra library (asfpy mail and pubsub, asfquart's EZT and YAML config), we decline it too.
2. **No separate web app.** A UI for attestations belongs inside ATR as ATR pages. If a standalone service is ever
   unavoidable, build it on `asfquart`.
3. **ATR is the first data source for project metadata.** PMCs already author security contact, threat model links,
   repositories, lifecycle page and version scheme in the `project:` block of `.asf.yaml`, which syncs to ATR. A
   `vsa-collect` provider should read these from ATR's public API instead of asking PMCs to repeat them in
   `project.json`.
4. **Pick ATR's library when we need the capability.** YAML: `strictyaml`. OpenPGP: `rpgp-py`. Canonical JSON for
   anything we sign or hash: `rfc8785`. Typed models: `pydantic`. SBOM: `cyclonedx-python-lib`. Logging: `structlog`.
5. **Keep the core light.** The library keeps only `jsonschema` (plus optional `pydantic`) as dependencies. New
   capabilities go behind optional extras so ATR and PMCs install only what they use.
6. **Keep conventions aligned.** Python 3.14, uv, ruff and pyright with ATR's settings, ATR's
   [code conventions](https://github.com/apache/tooling-trusted-releases/blob/main/atr/docs/code-conventions.md), and
   ATR's dependency hygiene (30-day lock freshness, `exclude-newer` cooldown, `pip-audit`).

## The repositories

### apache/infrastructure-asfquart (Infra)

A [Quart](https://quart.palletsprojects.com/) framework for ASF web apps: `asfquart.construct()`, ASF OAuth
(`oauth.apache.org`), cookie sessions carrying the user's committees and PMC memberships, `auth.require` decorators,
LDAP group checks, EZT templates, hot reload. Users include ATR, the Infra reporting dashboard and the self-serve portal.

How ATR uses it ([atr/docs/asf-modules.md](https://github.com/apache/tooling-trusted-releases/blob/main/atr/docs/asf-modules.md)):
app construction, sessions, OAuth and `auth.require(Requirements.committer)`, and `ASFQuartException` for HTTP errors.
ATR does **not** use its EZT templates (Jinja2 instead), YAML config (class-based config), bearer-token handler (own
JWT), LDAP auth path (own `ldap` module) or `runx()` dev server (Hypercorn).

**For vsa:** any web UI (for example a page where a PMC reviews or completes its CRA answers, or a view of a release's
attestation) should be an ATR page, built the ATR way: server-side rendering, Jinja2 templates, `htpy` for programmatic
HTML, Pydantic-backed forms through ATR's `form` module, Bootstrap styling, TypeScript only where unavoidable (see
[atr/docs/user-interface.md](https://github.com/apache/tooling-trusted-releases/blob/main/atr/docs/user-interface.md)).
`vsa` supplies the logic (models, validation, assembly) as library calls; ATR supplies the pages. A standalone service
would use `asfquart` for login and authorization, never a hand-rolled OAuth flow.

### apache/infrastructure-asfpy (Infra)

Infra's general helper library (PyPI `asfpy`): `pubsub` (ASF PubSub client), `messaging` (email), `aioldap` and
`clitools` (LDAP), `crypto` (Ed25519), `db` and `sqlite`, `justone` (single-instance lock), `stopwatch`, `syslog`,
`twatcher`, `whoami`.

How ATR uses it: not at all. It arrives only as an `asfquart` dependency. ATR wrote its own async, typed `mail` (it must
sign messages) and its own `pubsub` consumer.

**For vsa:** do not add `asfpy` to the library. If a future standalone job on an ASF VM must react to commits or
releases, or send mail, `asfpy.pubsub`, `asfpy.messaging` and `asfpy.justone` are the Infra-supported choices, but the
preferred design is that ATR triggers `vsa` at its own release phases, so this should not be needed.

### apache/infrastructure-asfyaml (Infra)

The parser that applies each repository's `.asf.yaml` (notifications, website publishing, GitHub settings) plus the
user-facing `.asf.yaml` documentation. It validates with `strictyaml` and offers `asfyaml-validate` (schema only, no
network) and `asfyaml-run`.

Its `project:` feature ([asfyaml/feature/project.py](https://github.com/apache/infrastructure-asfyaml/blob/main/asfyaml/feature/project.py))
pushes project metadata and release policy to ATR (`POST /api/project/config`) on push to the default branch. The
metadata block holds `key`, `committee`, `name`, `description`, `homepage`, `lifecycle_page`, `download_page`,
`bug_database`, `mailing_lists`, `security_contact` (must be `security@apache.org` or
`security@<committee>.apache.org`), `threat_model_link`, `threat_model_src_link`, `repositories`, `standards`,
`categories`, `programming_languages` and the version-scheme fields (`version_method`, `version_pattern`,
`cycle_match`, `calver_format`, `branch_template`). It can also take most fields from a linked DOAP file.

**For vsa:** this is already the PMC-authored, version-controlled path for most of the "who and where" answers our
attestation needs (security contact, threat model, lifecycle page, repositories, version cycles). It overlaps with
`project.json`. vsa reads those fields from ATR; CRA answers stay in `project.json` (see the decision below).

### apache/tooling-docs (Tooling)

The tooling.apache.org website (Pelican). Relevant pages: the ATR design doc, data model, platform and requirements,
`supply-chain.md`, and the draft
[ASF standard for scannable secret tokens](https://github.com/apache/tooling-docs/blob/main/content/pages/draft-asf-token-standard.md)
(`asf_<component>_<entropy><crc32>`). Doc hygiene follows `pre-commit` with markdownlint, yamllint and typos.

**For vsa:** if the tool ever issues tokens, use that token format. Our docs should pass the same markdown linters so
they can move to tooling.apache.org unchanged.

### apache/tooling-agenda (Tooling)

The Board Agenda Tool, live at agenda.apache.org. **Not reviewed:** the repository is not publicly readable from here
(`git ls-remote` asks for credentials), so it is private or not yet published. It is unlikely to matter for vsa beyond
being another Tooling app to borrow patterns from.

### Also reviewed

- **apache/tooling-trusted-releases (ATR).** The precedent for everything above. Its own data fetcher,
  [atr/datasources/apache.py](https://github.com/apache/tooling-trusted-releases/blob/main/atr/datasources/apache.py),
  reads the same Whimsy and projects.apache.org JSON our collector reads, with strict Pydantic models. Public API
  endpoints that need no token: `GET /api/project/get/<key>`, `/api/project/releases/<key>`,
  `/api/cle/project/<key>` (ECMA-428 lifecycle), `/api/catalog/project/<key>`. Its `attestable/` storage and
  `sealing.py` (signed records over `rfc8785` canonical JSON) are the obvious home and pattern for storing and signing
  our attestations inside ATR.
- **apache/tooling-releases-client** (`atr` CLI, PyPI name `apache-trusted-releases`). Carries copies of ATR's API
  models (`atrclient.models`), handles PAT and JWT auth, and uses `cyclopts`, `platformdirs`, `strictyaml` and
  `rpgp-py`. Its README warns the API schema and CLI are not stable yet.

## What this means for the current code

| Area | Today in vsa | Recommendation |
|---|---|---|
| Project metadata | `project.json` plus Whimsy and projects.apache.org providers | Add an ATR provider (public API) as the first source for the fields `.asf.yaml` already covers; keep `project.json` (one per product) for CRA-only answers |
| HTTP | stdlib `urllib` with an on-disk fixture cache | Keep. It stays deterministic and dependency-free. When running inside ATR, accept data passed in by ATR instead of fetching |
| Signature parsing | hand-written packet parsing in `vsa/signature.py` | Fine for reading the issuer fingerprint. For any real verification use `rpgp-py`, as ATR and its client do |
| JSON output | `json.dumps(indent=2)` | Fine for display. Anything we hash or sign must be `rfc8785` canonical JSON, as in ATR's `sealing.py` |
| YAML (if added) | none | `strictyaml`, never PyYAML, matching ATR, asfyaml and the client |
| CLI | `argparse` | Keep. ATR's own scripts use `argparse`; `cyclopts` only if we grow a client-style CLI |
| Web UI | none | ATR pages (asfquart, Jinja2, htpy, Pydantic forms, Bootstrap) |
| Logging | `print` | `structlog` if we add structured logs, so they merge with ATR's |

## Decided: where PMCs author CRA answers

Shane (review on PR #1, 2026-10-16): PMCs author CRA data in `project.json` (or a similar new per-PMC file), **not** in
`.asf.yaml`. vsa still reads the fields that `.asf.yaml` already syncs to ATR (security contact, threat model links,
repositories, lifecycle page, version scheme) from ATR first, so PMCs never enter them twice.

A PMC may ship several products with different languages or security backgrounds, so a PMC can have several answer
files (for example `product1.json`, `product2.json`). Designs must allow one file per product, not one per PMC. This
is tracked in the format README under "Issues to resolve with design".
