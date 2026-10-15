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
"""Source-neutral records of ASF data, and the interfaces that supply them.

The rules in resolve.py read only these records, never a source's own JSON. Moving a field to a
new source, such as the planned ASF RosterTool, an ATR project record or a security team
attestation, means writing one class that returns these records; no rule changes.
"""

import dataclasses
from typing import Protocol


@dataclasses.dataclass(frozen=True)
class CommitteeRecord:
    """The PMC that governs the project, from a roster source."""

    pmc: str
    name: str
    chair_name: str | None
    member_count: int
    source: str


@dataclasses.dataclass(frozen=True)
class LifecycleRecord:
    """Where the project publishes its support and end-of-life policy, such as an ATR CLE document."""

    policy_uri: str
    source: str


@dataclasses.dataclass(frozen=True)
class ProjectRecord:
    """Descriptive metadata about one project, as a DOAP file or ATR records it."""

    key: str
    pmc: str
    name: str | None
    homepage: str | None
    download_page: str | None
    repositories: tuple[str, ...]
    languages: tuple[str, ...]
    license: str | None
    versions: tuple[str, ...]
    source: str


@dataclasses.dataclass(frozen=True)
class SecurityRecord:
    """How to report a vulnerability in the project, such as ATR's security contact."""

    contact: str | None
    policy_uri: str | None
    source: str


class LifecycleSource(Protocol):
    def lifecycle(self, project: ProjectRecord) -> LifecycleRecord | None: ...


class ProjectSource(Protocol):
    def project(self, key: str) -> ProjectRecord: ...


class RosterSource(Protocol):
    def committee(self, pmc: str) -> CommitteeRecord | None: ...


class SecuritySource(Protocol):
    def security(self, project: ProjectRecord) -> SecurityRecord | None: ...


@dataclasses.dataclass(frozen=True)
class Sources:
    """One source per kind of data, each of which can be replaced on its own."""

    projects: ProjectSource
    roster: RosterSource
    security: SecuritySource
    lifecycle: LifecycleSource
