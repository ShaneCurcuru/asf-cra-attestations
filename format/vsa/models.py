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
# Generated from vsa/schema/vsa-lite.schema.json by scripts/models_generate.py
# Do not edit by hand: change the schema, then rerun the script

from datetime import date
from typing import Any, Literal

from pydantic import (
    AnyUrl,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    RootModel,
)


class HttpsUri(RootModel[AnyUrl]):
    root: AnyUrl


class MailtoOrHttpsUri(RootModel[AnyUrl]):
    root: AnyUrl


class LocalId(RootModel[str]):
    root: str = Field(
        ...,
        description=("Document-local identifier used to cross-reference artifacts and SBOMs."),
        pattern="^[a-z0-9][a-z0-9._-]*$",
    )


class Issuer(BaseModel):
    """
    AU.01: the legal entity issuing the attestation and its relationship to the project.
    """

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
    )
    name: str = Field(..., min_length=1)
    registered_address: str = Field(..., alias="registeredAddress", min_length=1)
    website: HttpsUri
    role: Literal["steward", "maintainer", "third-party"] = Field(
        ...,
        description=(
            "Issuer's relationship to the project, using CRA terms. 'steward' ="
            " open-source software steward (CRA Art. 3(14)); 'maintainer' = the project"
            " itself; 'third-party' = unaffiliated assessor."
        ),
    )
    relationship: str | None = Field(
        None,
        description=("Free-text explanation of the relationship (e.g. the PMC that governs the project)."),
    )


class Contact(BaseModel):
    """
    AU.02: the person issuing the attestation on the issuer's behalf, and their role. For the ASF this is the PMC chair, as the official representative of the PMC.
    """

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
    )
    name: str = Field(..., min_length=1)
    role: str = Field(..., min_length=1)
    email: EmailStr | None = None


class Project(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
    )
    name: str = Field(..., min_length=1)
    url: HttpsUri
    purl: str | None = Field(
        None,
        description="Package URL for the project's primary package, without version.",
        pattern="^pkg:",
    )


class Vcs(BaseModel):
    """
    Where the released source came from. A commit ID is strongly recommended because tags can move.
    """

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
    )
    type: Literal["git", "svn"]
    url: HttpsUri
    tag: str
    commit: str | None = Field(None, pattern="^([0-9a-f]{40}|[0-9a-f]{64}|r?[0-9]+)$")


class Vcs1(BaseModel):
    """
    Where the released source came from. A commit ID is strongly recommended because tags can move.
    """

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
    )
    type: Literal["git", "svn"]
    url: HttpsUri
    tag: str | None = None
    commit: str = Field(..., pattern="^([0-9a-f]{40}|[0-9a-f]{64}|r?[0-9]+)$")


class Release(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
    )
    version: str = Field(
        ...,
        description=("The single version this attestation is valid for. One document per release."),
        min_length=1,
    )
    release_date: date | None = Field(None, alias="releaseDate")
    announcement: HttpsUri | None = None
    vcs: Vcs | Vcs1 | None = Field(
        None,
        description=("Where the released source came from. A commit ID is strongly recommended because tags can move."),
    )


class Digests(BaseModel):
    """
    Cryptographic digests, lowercase hex, keyed by algorithm (in-toto DigestSet names). MD5 and SHA-1 are deliberately not allowed.
    """

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
    )
    sha256: str | None = Field(None, pattern="^[0-9a-f]{64}$")
    sha384: str | None = Field(None, pattern="^[0-9a-f]{96}$")
    sha512: str | None = Field(None, pattern="^[0-9a-f]{128}$")
    sha3_256: str | None = Field(None, alias="sha3-256", pattern="^[0-9a-f]{64}$")
    sha3_512: str | None = Field(None, alias="sha3-512", pattern="^[0-9a-f]{128}$")


class Signature(BaseModel):
    """
    A detached signature over the file it is attached to.
    """

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
    )
    format: Literal["openpgp", "sigstore-bundle", "cms"]
    uri: HttpsUri
    key_fingerprint: str | None = Field(
        None,
        alias="keyFingerprint",
        description=("Full OpenPGP v4 (40 hex) or v5/v6 (64 hex) fingerprint, uppercase, no spaces."),
        pattern="^([0-9A-F]{40}|[0-9A-F]{64})$",
    )
    keys_uri: HttpsUri | None = Field(
        None,
        alias="keysUri",
        description=("Where verifiers obtain the public key(s), e.g. the project's KEYS file."),
    )
    identity: str | None = Field(
        None,
        description=("For sigstore: the expected certificate identity (e.g. workflow URI or email)."),
    )


class Artifact(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
    )
    id: LocalId
    name: str = Field(..., description="File name as distributed.", min_length=1)
    role: Literal["source", "binary", "documentation", "other"] = Field(
        ...,
        description=(
            "'source' = the source release (for the ASF, the official act of release);"
            " 'binary' = compiled or packaged output."
        ),
    )
    official: bool | None = Field(
        None,
        description=(
            "True if the issuer treats this artifact as an official release (ASF:"
            " source packages voted on by the PMC). False for convenience binaries."
        ),
    )
    uri: HttpsUri
    purl: str | None = Field(None, pattern="^pkg:")
    size: int | None = Field(None, ge=0)
    digests: Digests
    signature: Signature | None = None
    sbom_refs: list[LocalId] | None = Field(
        None,
        alias="sbomRefs",
        description="ids of entries in subject.sboms that describe this artifact.",
    )


class Sbom(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
    )
    id: LocalId
    format: Literal["CycloneDX", "SPDX"]
    spec_version: str | None = Field(None, alias="specVersion", examples=["1.5", "2.3", "3.0"])
    media_type: str | None = Field(
        None,
        alias="mediaType",
        examples=["application/vnd.cyclonedx+json", "application/spdx+json"],
    )
    serial_number: str | None = Field(
        None,
        alias="serialNumber",
        description=(
            "CycloneDX serialNumber or SPDX documentNamespace, so the SBOM can be matched without downloading."
        ),
    )
    uri: HttpsUri
    digests: Digests
    signature: Signature | None = None


class Evidence1(BaseModel):
    """
    A pointer to where the claim can be checked. Either a URI, a reference to an artifact or SBOM in this document, or both.
    """

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
    )
    uri: MailtoOrHttpsUri
    ref: LocalId | None = None
    description: str | None = None


class Evidence2(BaseModel):
    """
    A pointer to where the claim can be checked. Either a URI, a reference to an artifact or SBOM in this document, or both.
    """

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
    )
    uri: MailtoOrHttpsUri | None = None
    ref: LocalId
    description: str | None = None


class Evidence(RootModel[Evidence1 | Evidence2]):
    root: Evidence1 | Evidence2 = Field(
        ...,
        description=(
            "A pointer to where the claim can be checked. Either a URI, a reference to"
            " an artifact or SBOM in this document, or both."
        ),
    )


class ControlCore(BaseModel):
    """
    Fields shared by every checklist item. 'met' corresponds to a ticked box. 'partial' means the practice is in place for some but not all of what the control asks, for example commit-then-review against QA.07. 'partial', 'not_met' and 'not_applicable' must be explained. 'not_assessed' means the PMC opted out and did not answer, and is only allowed when scope is 'minimal'.
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    status: Literal["met", "partial", "not_met", "not_applicable", "not_assessed"]
    evidence: list[Evidence] | None = None
    explanation: str | None = Field(None, min_length=1)


class LinkRule(RootModel[Any]):
    root: Any = Field(
        ...,
        description=(
            "Rule for items whose template line asks for a link: a 'met' status must carry at least one evidence entry."
        ),
    )


class Control(BaseModel):
    """
    A checklist item.
    """

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
    )
    status: Literal["met", "partial", "not_met", "not_applicable", "not_assessed"]
    evidence: list[Evidence] | None = None
    explanation: str | None = Field(None, min_length=1)


class LinkedControl(ControlCore):
    """
    A checklist item whose template line asks for a link.
    """

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
    )


class SecurityContactControl(ControlCore):
    """
    VM.01: a met status must give a reporting contact; a private reporting route is recommended.
    """

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
    )
    contact: MailtoOrHttpsUri | None = None
    private_reporting_uri: HttpsUri | None = Field(None, alias="privateReportingUri")


class Controls(BaseModel):
    """
    Tier 1 checklist items GV.01-EL.01. Every item must be present, so a missing answer is a validation error rather than a silent gap.
    """

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
    )
    gv_01: LinkedControl = Field(..., alias="GV.01", description="MUST include a contribution guideline.")
    gv_02: Control = Field(
        ...,
        alias="GV.02",
        description="Contribution guideline SHOULD set a quality standard.",
    )
    gv_03: LinkedControl = Field(..., alias="GV.03", description="MUST document usage and intended purpose.")
    le_01: LinkedControl = Field(
        ...,
        alias="LE.01",
        description="MUST be publicly available under an open source license.",
    )
    le_02: Control = Field(
        ...,
        alias="LE.02",
        description="Dependencies SHOULD be available under open source licenses.",
    )
    qa_01: LinkedControl = Field(
        ...,
        alias="QA.01",
        description=("MUST list direct third-party dependencies (SBOM or lockfile), with checksums where applicable."),
    )
    qa_02: LinkedControl = Field(..., alias="QA.02", description="Source and change history MUST be public.")
    qa_03: LinkedControl = Field(
        ...,
        alias="QA.03",
        description="MUST document how to file a vulnerability report.",
    )
    qa_04: LinkedControl = Field(..., alias="QA.04", description="MUST include repeatable test procedures.")
    qa_05: Control = Field(
        ...,
        alias="QA.05",
        description=("If non-memory-safe code is used, MUST mitigate memory-safety vulnerabilities."),
    )
    qa_06: Control = Field(..., alias="QA.06", description="SHOULD have more than one active contributor.")
    qa_07: Control = Field(
        ...,
        alias="QA.07",
        description=("With >1 contributor, SHOULD require review of every change by a human non-author."),
    )
    br_01: LinkedControl = Field(..., alias="BR.01", description="MUST document how to build from source.")
    br_02: LinkedControl = Field(
        ...,
        alias="BR.02",
        description="Releases MUST have unique, monotonically increasing versions.",
    )
    br_03: LinkedControl = Field(
        ...,
        alias="BR.03",
        description=("Released assets MUST be distributed with documented integrity verification."),
    )
    br_04: LinkedControl = Field(
        ...,
        alias="BR.04",
        description="Releases MUST include a log of functional and security changes.",
    )
    vm_01: SecurityContactControl = Field(
        ..., alias="VM.01", description="MUST indicate at least one security contact."
    )
    vm_02: Control = Field(
        ...,
        alias="VM.02",
        description=("MUST publish discovered vulnerabilities in reasonable time, with mitigations."),
    )
    el_01: Control = Field(
        ...,
        alias="EL.01",
        description="Discontinuation of support SHOULD be communicated adequately.",
    )


class OptOut(BaseModel):
    """
    Why a PMC opted out of the full checklist, and when it must re-confirm. Required when scope is 'minimal'.
    """

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
    )
    reason: Literal["no-commercial-use", "research-or-experimental", "winding-down", "other"]
    statement: str = Field(
        ...,
        description="The PMC's own words, published in every minimal attestation.",
        min_length=1,
    )
    decided: date = Field(..., description="Date of the PMC decision.")
    decision_ref: HttpsUri = Field(
        ...,
        alias="decisionRef",
        description="The PMC decision in the mailing list archive.",
    )
    review_by: date = Field(
        ...,
        alias="reviewBy",
        description=("Date by which the PMC must re-confirm, at most 12 months after decided."),
    )


class AttestationId(RootModel[str]):
    root: str = Field(
        ...,
        description="Globally unique, stable identifier for this attestation document.",
        pattern=("^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"),
    )


class Template(BaseModel):
    """
    The human-readable checklist this document instantiates.
    """

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
    )
    id: Literal["orcwg-vsa-lite"]
    version: str = Field(..., examples=["0.1"])
    uri: HttpsUri | None = None
    basis: str | None = Field(None, examples=["BSI TR-03185-2"])


class Subject(BaseModel):
    """
    AU.03: the project and the exact release the attestation applies to, bound to its artifacts.
    """

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
    )
    project: Project
    release: Release
    artifacts: list[Artifact] = Field(
        ...,
        description=(
            "Every released file the attestation covers. Tooling matches a downloaded"
            " file to this attestation by digest."
        ),
        min_length=1,
    )
    sboms: list[Sbom] | None = Field(
        None,
        description=("SBOMs describing the artifacts. Referenced from artifact.sbomRefs and from QA.01 evidence."),
    )


class Attestation(BaseModel):
    """
    Machine-readable form of the ORC WG Tier 1 checklist (orcwg/cra-attestations proposals/template-lite.md v0.1, derived from BSI TR-03185-2). One document attests to one release of one project and binds that attestation to the release's artifacts by cryptographic digest, detached signature and SBOM. AU.01-AU.03 are carried by the issuer, contact and subject objects; GV/LE/QA/BR/VM/EL items are carried in controls.
    """

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
    )
    field_schema: str | None = Field(None, alias="$schema")
    schema_version: Literal["0.3.0"] = Field(
        ...,
        alias="schemaVersion",
        description="Version of this schema the document conforms to.",
    )
    template: Template = Field(..., description="The human-readable checklist this document instantiates.")
    attestation_id: str = Field(
        ...,
        alias="attestationId",
        description="Globally unique, stable identifier for this attestation document.",
        pattern=("^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"),
    )
    scope: Literal["full", "minimal"] = Field(
        ...,
        description=(
            "'full' when the PMC answered the checklist. 'minimal' when the PMC opted"
            " out: only automatically derived controls are answered, every other"
            " control is 'not_assessed', and optOut says why."
        ),
    )
    opt_out: OptOut | None = Field(None, alias="optOut")
    issued: AwareDatetime = Field(..., description="When the attestation was issued (RFC 3339).")
    valid_until: AwareDatetime | None = Field(
        None,
        alias="validUntil",
        description=(
            "Optional date after which the issuer no longer stands behind the"
            " attestation (e.g. end of support for this release line)."
        ),
    )
    supersedes: list[AttestationId] | None = Field(
        None,
        description=("attestationId values this document replaces (e.g. a corrected re-issue)."),
    )
    comment: str | None = Field(None, description="Free-text note from the issuer. Not interpreted by tooling.")
    issuer: Issuer
    contact: Contact
    subject: Subject
    controls: Controls
