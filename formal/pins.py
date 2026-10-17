#!/usr/bin/env python3
"""Source pins for the formal claims in formal/.

Every claim in formal/pins.toml is tied to the exact source it is about:

  rust-item   a Rust function, impl block or constant in this repository,
              identified by a marker string (e.g. "pub fn aocl_range"). The
              pinned text runs from the line containing the marker to the
              matching closing brace (or to the end of the line for items
              without a body). Only that text is hashed, so unrelated edits
              elsewhere in the file do not invalidate the pin.
  lean-file   a Lean source file containing the theorem(s).
  crate       a crates.io dependency, pinned by the checksum in Cargo.lock.
              This fixes the exact upstream source (Triton VM, twenty-first).
  upstream-item
              an item inside an upstream crate, pinned like rust-item against
              a git tag. Checked only with --upstream (needs network); the
              crate checksum above already pins the same code offline.

Usage:
  python3 formal/pins.py check              # fail if any local pin is stale
  python3 formal/pins.py check --upstream   # also verify upstream items
  python3 formal/pins.py update             # recompute hashes (after review!)

A stale pin means the code changed after the claim was checked. Re-examine
the claim, update the Lean model if needed, re-run the proofs, and only then
run `update`.
"""

import hashlib
import pathlib
import subprocess
import sys
import tempfile
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
PINS = ROOT / "formal" / "pins.toml"


def extract_item(text: str, marker: str) -> str:
    lines = text.splitlines()
    for start, line in enumerate(lines):
        if marker in line:
            break
    else:
        raise LookupError(f"marker not found: {marker!r}")
    depth, opened, out = 0, False, []
    for line in lines[start:]:
        out.append(line)
        for ch in line:
            if ch == "{":
                depth += 1
                opened = True
            elif ch == "}":
                depth -= 1
        if not opened and line.rstrip().endswith(";"):
            break  # item without a body, e.g. a constant
        if opened and depth == 0:
            break
    return "\n".join(out) + "\n"


def sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def cargo_lock_checksum(name: str, version: str) -> str:
    lock = (ROOT / "Cargo.lock").read_text()
    for block in lock.split("[[package]]"):
        if f'name = "{name}"\n' in block and f'version = "{version}"\n' in block:
            for line in block.splitlines():
                if line.startswith("checksum = "):
                    return line.split('"')[1]
    raise LookupError(f"{name} {version} not in Cargo.lock")


_clones: dict = {}


def upstream_text(repo: str, tag: str, path: str) -> str:
    key = (repo, tag)
    if key not in _clones:
        tmp = tempfile.mkdtemp()
        subprocess.run(["git", "clone", "-q", "--depth", "1", "--branch", tag, repo, tmp],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _clones[key] = pathlib.Path(tmp)
    return (_clones[key] / path).read_text()


def current(pin: dict, upstream: bool):
    kind = pin["kind"]
    if kind == "rust-item":
        return sha256(extract_item((ROOT / pin["file"]).read_text(), pin["item"]))
    if kind == "lean-file":
        return sha256((ROOT / pin["file"]).read_text())
    if kind == "crate":
        return cargo_lock_checksum(pin["name"], pin["version"])
    if kind == "upstream-item":
        if not upstream:
            return None
        return sha256(extract_item(upstream_text(pin["repo"], pin["tag"], pin["file"]), pin["item"]))
    raise ValueError(f"unknown pin kind {kind}")


def describe(pin: dict) -> str:
    if pin["kind"] == "crate":
        return f'{pin["name"]} {pin["version"]} (Cargo.lock)'
    where = pin.get("file", "")
    if pin["kind"] == "upstream-item":
        where = f'{pin["repo"].rsplit("/", 1)[-1]}@{pin["tag"]}:{where}'
    item = f' :: {pin["item"]}' if "item" in pin else ""
    return where + item


def main(argv):
    mode = argv[1] if len(argv) > 1 else "check"
    upstream = "--upstream" in argv
    doc = tomllib.loads(PINS.read_text())
    stale = 0
    for pin in doc["pin"]:
        try:
            now = current(pin, upstream or mode == "update")
        except (LookupError, OSError, subprocess.CalledProcessError) as err:
            print(f"ERROR  {pin['claims']}  {describe(pin)}: {err}")
            stale += 1
            continue
        if now is None:
            print(f"skip   {', '.join(pin['claims'])}  {describe(pin)} (use --upstream)")
            continue
        if mode == "update":
            pin["sha256"] = now
        elif now != pin["sha256"]:
            print(f"STALE  {', '.join(pin['claims'])}  {describe(pin)}")
            stale += 1
        else:
            print(f"ok     {', '.join(pin['claims'])}  {describe(pin)}")
    if mode == "update":
        PINS.write_text(render(doc))
        print("pins updated; review the diff before committing")
        return 0
    if stale:
        print(f"\n{stale} stale pin(s): the code changed after these claims were checked.")
        return 1
    print("\nall pins match")
    return 0


def render(doc: dict) -> str:
    header = PINS.read_text().split("[[pin]]")[0].rstrip()
    out = [header, ""]
    for pin in doc["pin"]:
        out.append("[[pin]]")
        for key in ("claims", "kind", "file", "item", "name", "version", "repo", "tag", "sha256"):
            if key in pin:
                val = pin[key]
                if isinstance(val, list):
                    out.append(f"{key} = [" + ", ".join(f'"{v}"' for v in val) + "]")
                else:
                    out.append(f'{key} = "{val}"')
        out.append("")
    return "\n".join(out)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
