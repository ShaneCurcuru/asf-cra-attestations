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
"""Typed access to attestations for ATR, using the pydantic models generated from the schema.

This module needs the optional models extra, which installs pydantic.
"""

import vsa.document as document
import vsa.models as models


def attestation(doc: document.Document) -> models.Attestation:
    """Check doc against the JSON Schema, then return it as a typed model.

    The schema is checked first because it is the definition of the format: it carries rules, such as
    which fields an opt-out or a status requires, that the generated models do not enforce.
    """
    errors = document.check(doc)
    if errors:
        raise document.InputError("; ".join(errors))
    return models.Attestation.model_validate(doc)


def dump(model: models.Attestation) -> document.Document:
    """Return model as a plain document, with the schema's field names, ready for document.dump."""
    return model.model_dump(mode="json", by_alias=True, exclude_none=True)
