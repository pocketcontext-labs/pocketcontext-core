#!/usr/bin/env python3
"""Show unapproved differences between shared non-Go files of two application checkouts.

The files stay per application (they are not a build dependency). Run this at
each release so a backup or release-script fix cannot land in one application
and silently miss the other. Application names are normalized before comparing.
Every hunk of the normalized diff must appear in the approved-hunks file; a new
hunk is printed and fails. Standard-library Python.

    python3 tools/shared_file_diff.py ATLAS_DIR CREW_DIR --approved tools/approved-hunks.txt
    python3 tools/shared_file_diff.py ATLAS_DIR CREW_DIR --approved FILE --update

Normalization replaces the listed application names (--name, repeatable) with a
placeholder. By default the two checkout folder names are used.
"""
import argparse
import difflib
from pathlib import Path
import re
import sys

# The shared files the design requires to stay comparable.
FILES = ['docker/entrypoint.py', 'scripts/release.py']
PLACEHOLDER = '<APP>'


def normalize(text, names):
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, PLACEHOLDER).replace(name.replace('-', '_'), PLACEHOLDER)
    return text.splitlines()


def hunks(a_lines, b_lines, name):
    """Yield (file, hunk text without @@ line numbers) for every changed region."""
    group = []
    for line in difflib.unified_diff(a_lines, b_lines, f'a/{name}', f'b/{name}', lineterm=''):
        if line.startswith(('---', '+++')):
            continue
        if line.startswith('@@'):
            if group:
                yield name, '\n'.join(group)
            group = []
            continue
        group.append(line)
    if group:
        yield name, '\n'.join(group)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('first', type=Path)
    parser.add_argument('second', type=Path)
    parser.add_argument('--approved', type=Path, required=True)
    parser.add_argument('--name', action='append', default=[], help='application name to normalize')
    parser.add_argument('--update', action='store_true', help='record the current diff as approved')
    args = parser.parse_args()
    names = args.name or [args.first.resolve().name, args.second.resolve().name]
    current, missing = [], []
    for name in FILES:
        paths = [args.first / name, args.second / name]
        if not all(path.is_file() for path in paths):
            missing.append(name)
            continue
        a, b = [normalize(path.read_text(encoding='utf-8'), names) for path in paths]
        current += [f'### {file}\n{hunk}' for file, hunk in hunks(a, b, name)]
    if missing:
        print('missing files: ' + ', '.join(missing))
        return 1
    if args.update:
        args.approved.write_text('\n\n'.join(current) + '\n', encoding='utf-8')
        print(f'recorded {len(current)} approved hunks')
        return 0
    approved = args.approved.read_text(encoding='utf-8').split('\n\n') if args.approved.is_file() else []
    approved = {item.strip() for item in approved}
    new = [hunk for hunk in current if hunk.strip() not in approved]
    for hunk in new:
        print(hunk + '\n')
    if new:
        print(f'FAIL - {len(new)} unapproved hunks; review them and either port the change or record it with --update')
        return 1
    print(f'ok - {len(current)} hunks, all approved')
    return 0


if __name__ == '__main__':
    sys.exit(main())
