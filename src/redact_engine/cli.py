"""``redact-engine`` command line.

===== =====================================================================
0     projection written (and verified, with ``--verify``)
4     source refused: missing, symlinked, or not a regular file
5     verification failed: a pre-redaction value survived into the output
6     usage error
===== =====================================================================

Output layout, and the modes are not incidental:

``<out>/safe/events.jsonl``        0600, projection only
``<out>/safe/summary.json``        0600, counts, no text at all
``<out>/consented/identity-map.json``  only with ``--identity-map``; reverses aliases
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from .alias import InsecureKeyFile, load_or_create, new_key
from .projection import DEFAULT_FIELDS, Redactor, leaked_kinds
from .rules import DEFAULT_RULES, rules_for, zh_cue_rules
from .sources import UnsafeSource, discover_segment_files, events_from_jsonl

SAFE_DIR = "safe"
CONSENTED_DIR = "consented"


def _private_dir(path: Path) -> Path:
    """Create a directory with owner-only mode, and only tighten what we created.

    An existing directory handed to us is not ours to re-permission: ``--out .`` or
    an identity map written next to the source would otherwise chmod the caller's
    working directory (possibly the home directory) to 0700 and break unrelated
    software.
    """
    if path.is_symlink():
        raise UnsafeSource(f"refusing symlinked output directory: {path}")
    if path.exists():
        if not path.is_dir():
            raise UnsafeSource(f"not a directory: {path}")
        return path
    path.mkdir(parents=True, mode=0o700)
    os.chmod(path, 0o700)
    return path


def _write_private(path: Path, text: str) -> None:
    if path.is_symlink():
        raise UnsafeSource(f"refusing to write through a symlink: {path}")
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.chmod(path, 0o600)


def _load_mapping(path: str | None) -> dict[str, str]:
    if not path:
        return {"timestamp": "timestamp", "app": "app", "text": "text"}
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    for required in ("app", "text"):
        if required not in data:
            raise SystemExit(f"error: mapping must define {required!r}")
    return data


def _build_rules(args: argparse.Namespace):
    rules = list(rules_for(None if not args.kind else args.kind.split(",")))
    if args.zh_cues:
        rules.extend(zh_cue_rules())
    return tuple(rules)


def cmd_init_key(args: argparse.Namespace) -> int:
    key, created = load_or_create(args.key, overwrite=False)
    print(f"{'created' if created else 'using existing'} key: {args.key} ({len(key)} bytes, mode 0600)")
    return 0


def cmd_redact_text(args: argparse.Namespace) -> int:
    key, _ = load_or_create(args.key)
    redactor = Redactor(key, _build_rules(args), stable=not args.unstable)
    text = sys.stdin.read()
    result = redactor.redact(text)
    sys.stdout.write(result.text)
    if not sys.stdout.isatty():
        sys.stdout.write("\n")
    if args.stats:
        print(json.dumps(result.counts, ensure_ascii=False), file=sys.stderr)
    return 0


def cmd_project(args: argparse.Namespace) -> int:
    # validated before anything is opened: the identity map is written lazily as
    # subjects are encountered, so a bare filename would create it in the caller's
    # working directory *before* any end-of-command check could object
    identity_target = _identity_target(args.identity_map) if args.identity_map else None
    key, created = load_or_create(args.key)
    redactor = Redactor(
        key,
        _build_rules(args),
        stable=not args.unstable,
        persist_map=identity_target,
    )
    mapping = _load_mapping(args.mapping)
    fields = tuple(args.fields.split(",")) if args.fields else DEFAULT_FIELDS

    sources: list[Path]
    if args.source:
        sources = [Path(args.source)]
    elif args.root:
        sources = discover_segment_files(args.root, pattern=args.pattern)
        if not sources:
            # explicitly not "nothing happened": an empty glob means the recorder
            # is not writing where we are looking, which is a coverage gap, not a
            # quiet period
            print(json.dumps({"status": "no-records", "coverage_assessed": False,
                              "root": args.root, "pattern": args.pattern}, ensure_ascii=False))
            return 0
    else:
        print("error: give --source FILE or --root DIR", file=sys.stderr)
        return 6

    out = Path(args.out)
    if out.is_symlink():
        raise UnsafeSource(f"refusing symlinked output root: {out}")
    safe = _private_dir(out / SAFE_DIR)
    events_path = safe / "events.jsonl"
    if events_path.is_symlink():
        raise UnsafeSource(f"refusing symlinked output: {events_path}")
    # --verify must not inherit --kind's narrowing: an auditor with the full
    # default rule set harvests candidate secrets from the *input*, so narrowing
    # the active rules makes verification fail instead of quietly passing
    audit_rules = tuple(DEFAULT_RULES) + (zh_cue_rules() if args.zh_cues else ())
    auditor = Redactor(new_key(), audit_rules, stable=False)

    written = 0
    events_path.unlink(missing_ok=True)
    descriptor = os.open(str(events_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as sink:
        for source in sources:
            for event in events_from_jsonl(source, mapping, limit=args.limit):
                for name in fields:
                    value = event.get(name)
                    if isinstance(value, str):
                        auditor.redact(value)
                projected = redactor.project(event, fields)
                if not projected:
                    continue
                sink.write(json.dumps(projected, ensure_ascii=False) + "\n")
                written += 1
                if args.max_events and written >= args.max_events:
                    break
            if args.max_events and written >= args.max_events:
                break
    os.chmod(events_path, 0o600)

    payload = {
        "events": written,
        "sources": sorted({s.name for s in sources}),
        "source_count": len(sources),
        "fields": list(fields),
        "aliasing": "per-run" if args.unstable else "stable",
        "identity_map": bool(args.identity_map),
        "key": "created" if created else "existing",
        "rule_kinds": sorted({rule.kind for rule in redactor.rules}),
        "redactions": dict(sorted(redactor.hit_counts.items())),
        "coverage_assessed": False,
    }
    summary = safe / "summary.json"
    summary.unlink(missing_ok=True)
    _write_private(summary, json.dumps(payload, ensure_ascii=False, indent=1))

    if identity_target is not None:
        _guard_repo(identity_target.parent)

    if args.verify:
        body = events_path.read_text(encoding="utf-8")
        kinds = leaked_kinds(body, auditor.all_hits)
        if kinds:
            # the projection is unsafe: keep it on disk and report a pass would be
            # the exact inverse of what --verify is for
            events_path.unlink(missing_ok=True)
            summary.unlink(missing_ok=True)
            total = sum(kinds.values())
            print(f"LEAK CHECK FAILED: {total} value(s) survived with the active rules: "
                  f"{', '.join(f'{k} x{n}' for k, n in sorted(kinds.items()))}. "
                  "Output removed. Widen --kind or drop the narrowing.", file=sys.stderr)
            return 5

    print(json.dumps(payload, ensure_ascii=False))
    return 0


def _identity_target(raw: str) -> Path:
    """The reversible map needs an explicit directory, not a bare filename.

    A bare name resolves to the current working directory, and this command would
    then create-or-tighten that directory and drop a .gitignore into it -- silently
    re-permissioning wherever the operator happened to be standing.
    """
    target = Path(raw).expanduser()
    if str(target.parent) in ("", "."):
        raise ValueError("--identity-map needs a path with a directory component, "
                         f"got {raw!r} (it would land in the current directory)")
    _private_dir(target.parent)
    return target


def _guard_repo(directory: Path) -> None:
    """Keep the reversible map out of version control by default."""
    marker = directory / ".gitignore"
    if marker.is_symlink():
        return
    if not marker.exists():
        marker.write_text("# written by redact-engine: this directory reverses the aliases\n*\n", encoding="utf-8")
        os.chmod(marker, 0o600)
        return
    text = marker.read_text(encoding="utf-8")
    if "*" not in text.split():
        with open(marker, "a", encoding="utf-8") as handle:
            handle.write("*\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="redact-engine", description="Local-only redaction.")
    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument("--key", required=True, help="HMAC alias key file (created 0600 if absent)")
    shared.add_argument("--kind", help="comma-separated rule kinds to enable (default: all)")
    shared.add_argument("--zh-cues", action="store_true",
                        help="add heuristic Chinese person/place cues (not real NER)")
    shared.add_argument("--unstable", action="store_true",
                        help="fresh aliases every run, so the same subject cannot be correlated")

    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init-key", help="create or report the alias key")
    init.add_argument("--key", required=True)
    init.set_defaults(func=cmd_init_key)

    text = sub.add_parser("redact-text", parents=[shared], help="stdin -> redacted stdout")
    text.add_argument("--stats", action="store_true", help="per-kind counts on stderr")
    text.set_defaults(func=cmd_redact_text)

    project = sub.add_parser("project", parents=[shared], help="activity stream -> safe projection")
    project.add_argument("--source", help="one JSONL file")
    project.add_argument("--root", help="directory searched with --pattern")
    project.add_argument("--pattern", default="**/events.jsonl")
    project.add_argument("--mapping", help="JSON file mapping fields to source paths")
    project.add_argument("--fields", help="comma-separated whitelist (default timestamp,app,text)")
    project.add_argument("--out", required=True, help="output root")
    project.add_argument("--limit", type=int, help="max events per source file")
    project.add_argument("--max-events", type=int, help="global cap")
    project.add_argument("--identity-map", metavar="PATH",
                         help="ALSO write a reversible map (0600, gitignored, refuses symlinks)")
    project.add_argument("--verify", action="store_true",
                         help="re-read the output and fail if any raw value survived")
    project.set_defaults(func=cmd_project)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (UnsafeSource, InsecureKeyFile) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 4
    except AssertionError as exc:
        print(f"LEAK CHECK FAILED: {exc}", file=sys.stderr)
        return 5
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 6


if __name__ == "__main__":
    sys.exit(main())
