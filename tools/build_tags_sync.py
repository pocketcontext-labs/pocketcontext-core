#!/usr/bin/env python3
"""Keep build-tags.txt in step with the tailcat release in go.mod.

The recorded pair in tools/build-tags.sum names a tailcat version and the digest
of build-tags.txt. A change to the tag set without a tailcat version change
fails (the rule from the applications). Update the record only together with a
tailcat upgrade:

    python3 tools/build_tags_sync.py          # check
    python3 tools/build_tags_sync.py --update # record after changing tailcat
"""
import argparse
import hashlib
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
RECORD = ROOT / 'tools' / 'build-tags.sum'


def state():
    version = re.search(r'github\.com/tailscale/tailcat (v\S+)', (ROOT / 'go.mod').read_text()).group(1)
    digest = hashlib.sha256((ROOT / 'build-tags.txt').read_bytes().replace(b'\r\n', b'\n')).hexdigest()
    return version, digest


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--update', action='store_true')
    args = parser.parse_args()
    version, digest = state()
    recorded_version, recorded_digest = RECORD.read_text().split()
    if args.update:
        if version == recorded_version and digest != recorded_digest:
            print('FAIL - build-tags.txt changed without a tailcat version change')
            return 1
        RECORD.write_text(f'{version} {digest}\n')
        print(f'recorded {version}')
        return 0
    if (version, digest) != (recorded_version, recorded_digest):
        print(f'FAIL - tailcat {version} / tags {digest[:12]} differ from the record '
              f'{recorded_version} / {recorded_digest[:12]}; change them together and run --update')
        return 1
    print(f'ok - build-tags.txt matches tailcat {version}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
