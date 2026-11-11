#!/usr/bin/env python3
"""Fail if a product name or product vocabulary appears in non-test Go sources of core.

Core takes every name from appidentity.Identity, so the family name must only
occur in the module path. What an application is (a knowledge base, a task
board) is its own vocabulary too: core says "project", "profile" or the
identity's display name. Tests may use fixtures, but non-test code may not.
Standard-library Python.

    python3 tools/identity_scan.py
"""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
NEEDLE = 'pocketcontext'
MODULE = 'github.com/pocketcontext-labs/pocketcontext-core'
# Phrases that describe one application rather than any application.
VOCABULARY = ['knowledge base', 'knowledge-base', 'knowledge scope', 'multi-account']


def main():
    names = subprocess.run(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '*.go'], cwd=ROOT,
                           capture_output=True, check=True, text=True).stdout.split()
    bad = []
    count = 0
    for name in names:
        if name.endswith('_test.go'):
            continue
        count += 1
        for number, line in enumerate((ROOT / name).read_text(encoding='utf-8').splitlines(), 1):
            lowered = line.replace(MODULE, '').lower()
            if NEEDLE in lowered or any(phrase in lowered for phrase in VOCABULARY):
                bad.append(f'{name}:{number}: {line.strip()[:120]}')
    if bad:
        print('\n'.join(bad))
        print(f'FAIL - {len(bad)} product name or vocabulary occurrences in non-test Go code')
        return 1
    print(f'ok - no product name or vocabulary in {count} non-test Go files')
    return 0


if __name__ == '__main__':
    sys.exit(main())
