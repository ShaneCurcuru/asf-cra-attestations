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
"""Generate vsa/models.py, the pydantic models for ATR, from the JSON Schema.

  python scripts/models_generate.py          rewrite vsa/models.py
  python scripts/models_generate.py --check  exit 1 if vsa/models.py is out of date

The JSON Schema is the definition of the format, and these models are derived from it.
The generator version and every option are fixed, so the same schema always gives the same file.
"""

import argparse
import pathlib
import subprocess
import sys
import tempfile
from typing import Final

_ROOT: Final[pathlib.Path] = pathlib.Path(__file__).resolve().parent.parent
_SCHEMA_PATH: Final[pathlib.Path] = _ROOT / "vsa" / "schema" / "vsa-lite.schema.json"
_MODELS_PATH: Final[pathlib.Path] = _ROOT / "vsa" / "models.py"
_LICENSE_HEADER: Final[str] = "".join(
    _ROOT.joinpath("vsa", "__init__.py").read_text(encoding="utf-8").splitlines(keepends=True)[:16]
)
_FILE_HEADER: Final[str] = (
    _LICENSE_HEADER + "# Generated from vsa/schema/vsa-lite.schema.json by scripts/models_generate.py\n"
    "# Do not edit by hand: change the schema, then rerun the script"
)
_CODEGEN_OPTIONS: Final[tuple[str, ...]] = (
    "--input-file-type",
    "jsonschema",
    "--output-model-type",
    "pydantic_v2.BaseModel",
    "--target-python-version",
    "3.14",
    "--class-name",
    "Attestation",
    "--use-schema-description",
    "--use-standard-collections",
    "--use-union-operator",
    "--use-double-quotes",
    "--field-constraints",
    "--snake-case-field",
    "--allow-population-by-field-name",
    "--wrap-string-literal",
    "--enum-field-as-literal",
    "all",
    "--disable-timestamp",
    "--formatters",
    "builtin",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="fail if vsa/models.py is out of date")
    args = parser.parse_args(argv)

    generated = _generate()
    current = _MODELS_PATH.read_text(encoding="utf-8") if _MODELS_PATH.exists() else ""
    if args.check:
        if generated != current:
            print("vsa/models.py is out of date: run python scripts/models_generate.py", file=sys.stderr)
            return 1
        print("vsa/models.py is up to date")
        return 0

    _MODELS_PATH.write_text(generated, encoding="utf-8")
    print(f"wrote {_MODELS_PATH.relative_to(_ROOT)}")
    return 0


def _generate() -> str:
    with tempfile.TemporaryDirectory() as work:
        output = pathlib.Path(work) / "models.py"
        _run(
            "datamodel-codegen",
            "--input",
            str(_SCHEMA_PATH),
            "--output",
            str(output),
            "--custom-file-header",
            _FILE_HEADER,
            *_CODEGEN_OPTIONS,
        )
        # Ruff applies the repository's own formatting, so the file passes the usual checks
        _run("ruff", "check", "--quiet", "--fix-only", "--config", str(_ROOT / "pyproject.toml"), str(output))
        _run("ruff", "format", "--quiet", "--config", str(_ROOT / "pyproject.toml"), str(output))
        return output.read_text(encoding="utf-8")


def _run(*command: str) -> None:
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise SystemExit(f"{command[0]} failed: {result.stderr.strip()}")


if __name__ == "__main__":
    sys.exit(main())
