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
"""Command line interface for the collector.

  vsa-collect init KEY [--ref REF] [--version V --dist-dir URL ...] [--baseline FILE ...] [-o OUT]
        Write a draft project.json for the projects.apache.org project KEY, filling every value
        it can find in public ASF data. Controls a --baseline file answers (the ASF baseline, then
        any community baseline) are left to that baseline. Controls nobody answers are left out, so
        vsa generate refuses to run until the PMC answers them; --report lists each one and why.
  vsa-collect release VERSION --issued TIME --dist-dir URL ... [--tag T] [--commit C] [-o OUT]
        Write release-VERSION.json naming every artifact, signature and SBOM for VERSION in the
        listed download directories. TIME is the attestation date, normally when the vote passed.

Project, roster, security and lifecycle data come from swappable sources (see providers.py).
--records FILE replaces individual fields with values from another system, such as a RosterTool
export or an ATR project record, without code changes.

Every network response can be kept with --cache DIR, and --offline then repeats a run from the
cache alone, giving byte-identical output. Exit status is 0 on success, 1 on an input error.
"""

import argparse
import pathlib
import sys
from collections.abc import Sequence

import vsa.collect.draft as draft
import vsa.collect.fetch as fetch
import vsa.collect.providers as providers
import vsa.document as document


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        fetcher = fetch.Fetcher(pathlib.Path(args.cache) if args.cache else None, args.offline)
        if args.cmd == "init":
            _init(fetcher, args)
        else:
            _release(fetcher, args)
    except (document.InputError, KeyError, ValueError, OSError) as e:
        print(f"error: {e!r}" if isinstance(e, KeyError) else f"error: {e}", file=sys.stderr)
        return 1
    return 0


def _init(fetcher: fetch.Fetcher, args: argparse.Namespace) -> None:
    if args.dist_dir and (not args.version):
        raise document.InputError("--dist-dir needs --version, to pick out that release's SBOMs")
    options = draft.Options(
        key=args.key,
        version=args.version,
        ref=args.ref,
        git_url=args.git_url,
        dist_dirs=tuple(args.dist_dir),
        baselines=tuple(args.baseline),
    )
    data = providers.default_sources(fetcher, args.projects_base)
    for path in args.records:
        data = providers.Overlay(data, path).sources()
    project, report = draft.project_draft(fetcher, data, options)
    _write(args.output, project)
    if args.report:
        pathlib.Path(args.report).write_text(document.dump(report), encoding="utf-8")
    for name in report["toAnswer"]:
        entry = report["controls"].get(name) or report["fields"][name]
        print(f"needs answer: {name}: {entry['note']}", file=sys.stderr)


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="vsa-collect", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--cache", help="directory that keeps every network response")
    parser.add_argument("--offline", action="store_true", help="read only from --cache")
    commands = parser.add_subparsers(dest="cmd", required=True)
    init_parser = commands.add_parser("init")
    init_parser.add_argument("key", help="project key in projects.json, for example commons-lang")
    init_parser.add_argument("--ref", help="git tag or branch whose files are checked")
    init_parser.add_argument("--git-url", help="GitHub repository, when projects.json gives none")
    init_parser.add_argument("--version", help="release version whose files --dist-dir holds")
    init_parser.add_argument("--dist-dir", action="append", default=[], help="download directory URL")
    init_parser.add_argument(
        "--baseline", action="append", default=[], help="baseline file, broadest first; its controls are left out"
    )
    init_parser.add_argument("--projects-base", default=providers.PROJECTS_BASE, help="where projects.json lives")
    init_parser.add_argument(
        "--records", action="append", default=[], help="JSON file whose record fields replace the sources' values"
    )
    init_parser.add_argument("-o", "--output", help="write here instead of stdout")
    init_parser.add_argument("--report", help="write the JSON report here")
    release_parser = commands.add_parser("release")
    release_parser.add_argument("version")
    release_parser.add_argument("--issued", required=True, help="RFC 3339 time, for example 2026-10-15T00:00:00Z")
    release_parser.add_argument("--dist-dir", action="append", required=True, help="download directory URL")
    release_parser.add_argument("--release-date", help="YYYY-MM-DD")
    release_parser.add_argument("--tag")
    release_parser.add_argument("--commit")
    release_parser.add_argument("--source", action="append", default=[], help="file name pattern of a source package")
    release_parser.add_argument("-o", "--output", help="write here instead of stdout")
    return parser.parse_args(argv)


def _release(fetcher: fetch.Fetcher, args: argparse.Namespace) -> None:
    extra = {"releaseDate": args.release_date, "tag": args.tag, "commit": args.commit}
    doc = draft.release_draft(
        fetcher,
        args.version,
        args.issued,
        tuple(args.dist_dir),
        {k: v for k, v in extra.items() if v},
        tuple(args.source),
    )
    _write(args.output, doc)


def _write(output: str | None, doc: document.Document) -> None:
    if output:
        pathlib.Path(output).write_text(document.dump(doc), encoding="utf-8")
        return
    sys.stdout.write(document.dump(doc))
