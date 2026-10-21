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
"""Command line interface for PMCs and release managers.

  vsa generate SETTINGS RELEASE DIR [-I INCLUDE]... [-o OUT]
        Build an attestation from the JSON input files and the release files in DIR.
        SETTINGS is the project or product file. Its "parent", and each parent's own parent,
        are loaded first and layered beneath it; a parent is found next to the file naming it,
        or else in each INCLUDE directory. A field a parent lists as "required" may not change.
        Digests, sizes, OpenPGP key fingerprints and SBOM serial numbers are computed from
        the files, and the same inputs always give byte-identical output.
  vsa validate FILE
        Check FILE against the schema and the cross-reference rules.
  vsa verify FILE [DIR]
        Also hash every artifact and SBOM, reading from DIR or else downloading.
  vsa intoto FILE
        Print an in-toto v1 Statement with the attestation as its predicate.

Exit status is 0 when valid, 1 when invalid, and 2 on a usage error.
No network access is needed except for verify without DIR.
"""

import argparse
import pathlib
import sys
from collections.abc import Sequence

import vsa.assemble as assemble
import vsa.digests as digests
import vsa.document as document
import vsa.intoto as intoto
import vsa.settings as settings


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        doc = _load_input(args)
    except (document.InputError, KeyError, ValueError, OSError) as e:
        print(f"error: {e!r}" if isinstance(e, KeyError) else f"error: {e}", file=sys.stderr)
        return 1

    errors = document.check(doc)
    if (args.cmd == "verify") and (not errors):
        errors = digests.verify(doc, args.dir)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1

    _write_output(args, doc)
    return 0


def _load_input(args: argparse.Namespace) -> document.Document:
    if args.cmd == "generate":
        layers = settings.chain(args.settings, include=args.include)
        return assemble.attestation(layers, document.load(args.release), args.dir)
    return intoto.unwrap(document.load(args.file))


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="vsa", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    commands = parser.add_subparsers(dest="cmd", required=True)
    generate_parser = commands.add_parser("generate")
    generate_parser.add_argument("settings", help="project or product settings file; its parents are loaded first")
    generate_parser.add_argument("release")
    generate_parser.add_argument("dir", help="directory holding the release files, signatures and SBOMs")
    generate_parser.add_argument("-o", "--output", help="write here instead of stdout")
    generate_parser.add_argument(
        "-I",
        "--include",
        action="append",
        default=[],
        help="directory to look for parent settings files in; may be repeated",
    )
    for name in ("validate", "intoto"):
        commands.add_parser(name).add_argument("file")
    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("file")
    verify_parser.add_argument("dir", nargs="?")
    return parser.parse_args(argv)


def _write_output(args: argparse.Namespace, doc: document.Document) -> None:
    if args.cmd == "intoto":
        sys.stdout.write(document.dump(intoto.wrap(doc)))
        return
    if args.cmd == "verify":
        print(f"{args.file}: valid, and every digest matches")
        print("Verify OpenPGP signatures with gpg --verify and the listed KEYS file")
        return
    if args.cmd == "validate":
        print(f"{args.file}: valid")
        return
    if args.output:
        pathlib.Path(args.output).write_text(document.dump(doc), encoding="utf-8")
        return
    sys.stdout.write(document.dump(doc))
