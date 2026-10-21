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

  vsa generate SETTINGS RELEASE DIR [-I INCLUDE]... [--root-sha512 HEX]... [--keys KEYS] [-o OUT]
        Build an attestation from the JSON input files and the release files in DIR.
        SETTINGS is the project or product file. Its "parent", and each parent's own parent,
        are loaded first and layered beneath it; a parent is found next to the file naming it,
        or else in each INCLUDE directory. A field a parent lists as "required" may not change.
        --root-sha512 names the SHA-512 of the root settings file (at the ASF, baseline/asf.json),
        and generation fails if the chain starts anywhere else; without it a settings file could
        name its own copy of the root. --keys checks every .asc against that KEYS file.
        Digests, sizes, OpenPGP key fingerprints and SBOM serial numbers are computed from
        the files, the SHA-512 of every input file is recorded, and the same inputs always
        give byte-identical output.
  vsa validate FILE
        Check FILE against the schema and the cross-reference rules.
  vsa verify FILE [DIR] [--keys KEYS] [--signature ASC] [--trust-prefix URL]... [--mirror OLD=NEW]...
        Also hash every artifact and SBOM, reading from DIR or else downloading, and check every
        OpenPGP signature. Keys come from KEYS, or else from each KEYS URL in the attestation,
        which must start with a trusted prefix (by default downloads.apache.org,
        archive.apache.org/dist and dist.apache.org/repos/dist/release). --signature also checks
        a detached signature over FILE itself. --digests-only skips signatures, and says so.
  vsa intoto FILE
        Print an in-toto v1 Statement with the attestation as its predicate.
  vsa diff OLD NEW
        List every answer that differs between two attestations, for the release vote email,
        and the SHA-512 of NEW, which is the exact document voters approve.

Exit status is 0 when valid, 1 when invalid, and 2 on a usage error.
No network access is needed except for verify without DIR, or without --keys.
"""

import argparse
import pathlib
import sys
from collections.abc import Sequence

import vsa.assemble as assemble
import vsa.diff as diff
import vsa.digests as digests
import vsa.document as document
import vsa.intoto as intoto
import vsa.keyring as keyring
import vsa.settings as settings
import vsa.verify as verify


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        if args.cmd == "diff":
            return _diff(args)
        raw, doc = _load_input(args)
        errors = document.check(doc) or intoto.check(raw)
        if (args.cmd == "verify") and (not errors):
            errors = _verify(args, doc)
    except (document.InputError, KeyError, ValueError, OSError) as e:
        print(f"error: {e!r}" if isinstance(e, KeyError) else f"error: {e}", file=sys.stderr)
        return 1
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1

    _write_output(args, doc)
    return 0


def _diff(args: argparse.Namespace) -> int:
    old = intoto.unwrap(document.load(args.old))
    data = pathlib.Path(args.new).read_bytes()
    new = intoto.unwrap(document.loads(data, args.new))
    lines = diff.changes(old, new)
    print(f"{args.new} sha512 {digests.sha512(data)}")
    print("\n".join(lines) if lines else "No answers changed.")
    return 0


def _generate(args: argparse.Namespace) -> document.Document:
    layers = settings.chain(args.settings, include=args.include)
    if args.root_sha512:
        settings.check_root(layers, args.root_sha512)
    else:
        print("warning: no --root-sha512, so the root settings file is not checked", file=sys.stderr)
    ring = keyring.load(pathlib.Path(args.keys).read_text(encoding="utf-8"), args.keys) if args.keys else None
    data = pathlib.Path(args.release).read_bytes()
    release = document.loads(data, args.release)
    return assemble.attestation(
        layers,
        release,
        args.dir,
        ring=ring,
        release_name=pathlib.Path(args.release).name,
        release_sha512=digests.sha512(data),
    )


def _load_input(args: argparse.Namespace) -> tuple[document.Document, document.Document]:
    if args.cmd == "generate":
        doc = _generate(args)
        return doc, doc
    raw = document.load(args.file)
    return raw, intoto.unwrap(raw)


def _mirror(value: str) -> tuple[str, str]:
    old, sep, new = value.partition("=")
    if (not sep) or (not old.startswith("https://")) or (not new.startswith("https://")):
        raise argparse.ArgumentTypeError("a mirror is OLD=NEW, two https:// URL prefixes")
    return old, new


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
    generate_parser.add_argument(
        "--root-sha512", action="append", default=[], help="SHA-512 the root settings file must have; may be repeated"
    )
    generate_parser.add_argument("--keys", help="KEYS file every signature must verify against")
    for name in ("validate", "intoto"):
        commands.add_parser(name).add_argument("file")
    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("file")
    verify_parser.add_argument("dir", nargs="?")
    verify_parser.add_argument("--keys", help="local KEYS file to check signatures with, instead of downloading")
    verify_parser.add_argument("--signature", help="detached OpenPGP signature over FILE itself")
    verify_parser.add_argument(
        "--trust-prefix", action="append", default=[], help="trusted KEYS URL prefix, replacing the defaults"
    )
    verify_parser.add_argument(
        "--mirror", action="append", default=[], type=_mirror, help="OLD=NEW URL prefix to try when OLD gives 404"
    )
    verify_parser.add_argument("--digests-only", action="store_true", help="skip signature checks")
    diff_parser = commands.add_parser("diff")
    diff_parser.add_argument("old", help="the project's previous attestation")
    diff_parser.add_argument("new", help="the attestation being voted on")
    return parser.parse_args(argv)


def _trusted_rings(args: argparse.Namespace, uris: list[str]) -> dict[str, keyring.Keyring]:
    # Keys never come from wherever the attestation says, only from a trusted prefix
    prefixes = tuple(args.trust_prefix) or keyring.TRUSTED_KEYS_PREFIXES
    untrusted = [u for u in uris if not keyring.is_trusted(u, prefixes)]
    if untrusted:
        raise document.InputError(f"KEYS URL not under a trusted prefix: {', '.join(untrusted)}")
    mirrors = (*args.mirror, *verify.MIRRORS)
    return {u: keyring.load(verify.fetch(u, None, mirrors).decode("utf-8"), u) for u in uris}


def _verify(args: argparse.Namespace, doc: document.Document) -> list[str]:
    mirrors = (*args.mirror, *verify.MIRRORS)
    if args.digests_only:
        return verify.files(doc, args.dir, None, mirrors)
    uris = verify.keys_uris(doc)
    own = keyring.load(pathlib.Path(args.keys).read_text(encoding="utf-8"), args.keys) if args.keys else None
    rings = dict.fromkeys(uris, own) if (own is not None) else _trusted_rings(args, uris)
    errors = verify.files(doc, args.dir, rings, mirrors)
    if args.signature:
        ring = own or next(iter(rings.values()), None)
        if ring is None:
            return [*errors, "--signature needs --keys, since the attestation names no KEYS file"]
        data = pathlib.Path(args.file).read_bytes()
        try:
            keyring.verify(ring, pathlib.Path(args.signature).read_bytes(), data, args.file)
        except document.InputError as e:
            errors.append(str(e))
    return errors


def _write_output(args: argparse.Namespace, doc: document.Document) -> None:
    if args.cmd == "intoto":
        sys.stdout.write(document.dump(intoto.wrap(doc)))
        return
    if args.cmd == "verify":
        if args.digests_only:
            print(f"{args.file}: valid, and every digest matches; signatures NOT checked")
            return
        checked = ", including the attestation's own," if args.signature else ""
        print(f"{args.file}: valid, every digest matches, and every signature{checked} verifies")
        return
    if args.cmd == "validate":
        print(f"{args.file}: valid")
        return
    if args.output:
        pathlib.Path(args.output).write_text(document.dump(doc), encoding="utf-8")
        return
    sys.stdout.write(document.dump(doc))
