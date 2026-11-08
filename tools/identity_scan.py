#!/usr/bin/env python3
"""Fail if a product name appears in non-test Go sources of core.

Core takes every name from appidentity.Identity, so the string below must only
occur in the module path. Tests may use fixtures, but non-test code may not.
Standard-library Python.

    python3 tools/identity_scan.py
"""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
NEEDLE = 'pocketcontext'
MODULE = 'github.com/pocketcontext-labs/pocketcontext-core'


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
            if NEEDLE in line.replace(MODULE, '').lower():
                bad.append(f'{name}:{number}: {line.strip()[:120]}')
    if bad:
        print('\n'.join(bad))
        print(f'FAIL - {len(bad)} product name occurrences in non-test Go code')
        return 1
    print(f'ok - no product name in {count} non-test Go files')
    return 0


if __name__ == '__main__':
    sys.exit(main())
