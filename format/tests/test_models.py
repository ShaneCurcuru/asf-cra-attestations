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

import copy
import pathlib
import shutil
import subprocess
import sys

import pytest

pytest.importorskip("pydantic")

import vsa.document as document
import vsa.models as models
import vsa.typed as typed

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_EXAMPLES = ("commons-lang3-3.17.0.vsa.json", "commons-lang3-3.17.0.minimal.vsa.json")


def test_attestation_rejects_what_only_the_schema_catches() -> None:
    doc = document.load(_ROOT / "examples" / "commons-lang3" / _EXAMPLES[0])
    broken = copy.deepcopy(doc)
    broken["controls"]["GV.01"] = {"status": "not_assessed"}
    # The generated models accept this, but the schema forbids not_assessed in a full attestation
    models.Attestation.model_validate(broken)
    with pytest.raises(document.InputError, match="not_assessed"):
        typed.attestation(broken)


@pytest.mark.parametrize("name", _EXAMPLES)
def test_attestation_round_trips_examples(name: str) -> None:
    doc = document.load(_ROOT / "examples" / "commons-lang3" / name)
    model = typed.attestation(doc)
    assert isinstance(model, models.Attestation)
    assert typed.dump(model) == doc


@pytest.mark.skipif(shutil.which("datamodel-codegen") is None, reason="needs the codegen dependency group")
def test_models_match_schema() -> None:
    script = _ROOT / "scripts" / "models_generate.py"
    result = subprocess.run([sys.executable, str(script), "--check"], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
