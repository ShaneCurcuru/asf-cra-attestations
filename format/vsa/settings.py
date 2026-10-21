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
"""Settings files that inherit from a parent, and the fields a parent requires.

Any settings file may name its parent with "parent", and the parent may name its own. The chain is
merged from the root down, so the file named on the command line wins. Nothing here knows which
file is the root: at the ASF it is baseline/asf.json, but another organisation can build its own
hierarchy.

A file may list fields under "required", as JSON Pointers (RFC 6901) such as "/issuer" or
"/controls/VM.01/status". Once a file requires a field, it is an error for any file below it to
change that field's value.
"""

import dataclasses
import os
import pathlib
from collections.abc import Sequence
from typing import Any, Final

import vsa.document as document

# Keys that describe one file, and are never inherited
LAYER_KEYS: Final[frozenset[str]] = frozenset({"name", "description", "parent", "required"})

_MISSING: Final[object] = object()


@dataclasses.dataclass(frozen=True)
class Layer:
    """One settings file, and where it came from, for error messages."""

    source: str
    doc: document.Document


def chain(path: str | pathlib.Path, include: Sequence[str | pathlib.Path] = ()) -> list[Layer]:
    """Load the settings file at path and every parent it names, root first.

    A parent is looked for relative to the file that names it, then in each include directory in
    order (see find), so that a project in its own repository can name a parent kept elsewhere.
    """
    layers: list[Layer] = []
    seen: list[pathlib.Path] = []
    current: pathlib.Path | None = pathlib.Path(path)
    while current is not None:
        resolved = current.resolve()
        if resolved in seen:
            loop = " -> ".join(layer.source for layer in layers)
            raise document.InputError(f"settings parents form a loop: {loop} -> {current}")
        seen.append(resolved)
        doc = document.load(current)
        layers.append(Layer(str(current), doc))
        current = _parent_path(current, doc, include)
    return layers[::-1]


def find(name: str, directory: str | pathlib.Path, include: Sequence[str | pathlib.Path] = ()) -> pathlib.Path:
    """Return the settings file a "parent" of name refers to, from a file in directory.

    It is looked for in directory first, then in each include directory in order.
    """
    candidates = [pathlib.Path(directory) / name, *(pathlib.Path(d) / name for d in include)]
    for candidate in candidates:
        if candidate.is_file():
            # Drop any "..", so that error messages name the file plainly
            return pathlib.Path(os.path.normpath(candidate))
    raise document.InputError(f"parent {name} not found in {directory} or in any include directory")


def merge(layers: Sequence[Layer]) -> document.Document:
    """Merge layers, root first, into one settings document, and enforce every required field.

    Each top-level object is merged one level deep: a layer replaces each key it sets, whole. So a
    layer replaces a control by its ID, and an issuer field by its name. Any other value is replaced
    whole. Every violation in any layer is reported together.
    """
    merged: document.Document = {}
    # Each required pointer, with the value it was locked to and the layer that locked it
    locked: dict[str, tuple[Any, str]] = {}
    errors: list[str] = []
    for layer in layers:
        merged = _apply(merged, layer.doc)
        errors.extend(_changed(locked, merged, layer.source))
        errors.extend(_lock(locked, merged, layer))
    if errors:
        raise document.InputError("; ".join(errors))
    return merged


def _apply(merged: document.Document, doc: document.Document) -> document.Document:
    out = dict(merged)
    for key, value in doc.items():
        if key in LAYER_KEYS:
            continue
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = {**out[key], **value}
        else:
            out[key] = value
    return out


def _changed(locked: dict[str, tuple[Any, str]], merged: document.Document, source: str) -> list[str]:
    return [
        f"{source} changes {pointer}, which {owner} requires"
        for pointer, (value, owner) in locked.items()
        if _get(merged, pointer) != value
    ]


def _get(doc: Any, pointer: str) -> Any:
    value = doc
    for token in _tokens(pointer):
        if isinstance(value, dict) and (token in value):
            value = value[token]
        elif isinstance(value, list) and token.isdigit() and (int(token) < len(value)):
            value = value[int(token)]
        else:
            return _MISSING
    return value


def _lock(locked: dict[str, tuple[Any, str]], merged: document.Document, layer: Layer) -> list[str]:
    required = layer.doc.get("required", [])
    if (not isinstance(required, list)) or (not all(isinstance(p, str) for p in required)):
        return [f"{layer.source}: required must be a list of JSON Pointers"]
    errors: list[str] = []
    for pointer in required:
        value = _get(merged, pointer)
        if value is _MISSING:
            errors.append(f"{layer.source} requires {pointer}, but no settings file sets it")
        elif pointer not in locked:
            locked[pointer] = (value, layer.source)
    return errors


def _parent_path(
    child: pathlib.Path, doc: document.Document, include: Sequence[str | pathlib.Path]
) -> pathlib.Path | None:
    parent = doc.get("parent")
    if parent is None:
        return None
    if not isinstance(parent, str):
        raise document.InputError(f"{child}: parent must be a file path")
    return find(parent, child.parent, include)


def _tokens(pointer: str) -> list[str]:
    # A JSON Pointer such as /controls/VM.01/status, with ~1 for / and ~0 for ~ inside a token
    if (not pointer.startswith("/")) or (pointer == "/"):
        raise document.InputError(f"required field {pointer!r} must be a JSON Pointer such as /issuer")
    return [t.replace("~1", "/").replace("~0", "~") for t in pointer[1:].split("/")]
