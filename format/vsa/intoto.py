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
"""Wrapping attestations as in-toto v1 Statements for signing and transparency logs."""

from typing import Final

import vsa.document as document

# Beta identifier under the ASF Tooling site, matching the schema $id
PREDICATE_TYPE: Final[str] = "https://tooling.apache.org/cra/vsa-lite/v0.4"
STATEMENT_TYPE: Final[str] = "https://in-toto.io/Statement/v1"


def check(doc: document.Document) -> list[str]:
    """Return errors when doc is a Statement whose subjects are not the predicate's artifacts.

    A bare attestation has no Statement around it, so it gives no errors here.
    """
    if doc.get("_type") != STATEMENT_TYPE:
        return []
    errors: list[str] = []
    if doc.get("predicateType") != PREDICATE_TYPE:
        errors.append(f"predicateType is {doc.get('predicateType')}, not {PREDICATE_TYPE}")
    if doc.get("subject") != wrap(doc["predicate"])["subject"]:
        errors.append("Statement subjects do not match the attestation's subject.artifacts")
    return errors


def unwrap(doc: document.Document) -> document.Document:
    """Return the attestation, whether doc is a bare attestation or an in-toto Statement."""
    if doc.get("_type") == STATEMENT_TYPE:
        return doc["predicate"]
    return doc


def wrap(doc: document.Document) -> document.Document:
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": a["name"], "digest": a["digests"], "uri": a["uri"]} for a in doc["subject"]["artifacts"]],
        "predicateType": PREDICATE_TYPE,
        "predicate": {k: v for k, v in doc.items() if k != "$schema"},
    }
