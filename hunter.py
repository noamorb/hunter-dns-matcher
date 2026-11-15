#!/usr/bin/env python3
"""Offline DNS exact-domain matcher. Python 3 standard library + TShark."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

FIELDS = ['frame.number', 'ip.src', 'ipv6.src', 'ip.dst', 'ipv6.dst',
          'dns.flags.response', 'dns.qry.name', 'dns.a', 'dns.aaaa']

def normalize(name):
    name = name.strip().lower()
    return name[:-1] if name.endswith('.') else name

def read_indicators(path):
    result = set()
    for line in path.read_text(encoding='utf-8-sig').splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        name = normalize(line)
        labels = name.split('.')
        if len(name) > 253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', s) for s in labels):
            raise ValueError('Invalid domain (use ASCII/punycode, not URLs): ' + line)
        result.add(name)
    if not result:
        raise ValueError('Indicator list is empty')
    return result

def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def write_status(out, data):
    temporary = out / 'status.tmp'
    temporary.write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')
    temporary.replace(out / 'status.json')

def run(capture, indicator_file, out):
    # Validate before creating output or invoking TShark.
    indicators = read_indicators(indicator_file)
    with capture.open('rb'):
        pass
    binary = shutil.which('tshark')
    if not binary:
        raise ValueError('tshark is not installed')
    out.mkdir()  # Refuse to overwrite any existing output directory.
    status = {'status': 'running', 'version': '2.0', 'scope': 'DNS question names only'}
    try:
        write_status(out, status)
        before = digest(capture)
        command = [binary, '-n', '-r', str(capture.resolve()), '-Y', 'dns',
                   '-T', 'fields', '-E', 'header=y', '-E', 'separator=,',
                   '-E', 'quote=d', '-E', 'occurrence=a', '-E', 'aggregator=,']
        for field in FIELDS:
            command.extend(['-e', field])
        with (out / 'dns_evidence.csv').open('w', encoding='utf-8') as raw, \
             (out / 'tshark.log').open('w', encoding='utf-8') as log:
            subprocess.run(command, stdout=raw, stderr=log, check=True)
        if digest(capture) != before:
            raise ValueError('Capture changed during analysis; results are invalid')
        names, matches = set(), set()
        count = dns_rows = 0
        with (out / 'dns_evidence.csv').open(newline='', encoding='utf-8') as raw, \
             (out / 'match_evidence.csv').open('w', newline='', encoding='utf-8') as evidence:
            reader = csv.DictReader(raw)
            if reader.fieldnames != FIELDS:
                raise ValueError('Unexpected TShark output columns')
            writer = csv.DictWriter(evidence, fieldnames=['matched_domain'] + FIELDS)
            writer.writeheader()
            for row in reader:
                if None in row or any(v is None for v in row.values()):
                    raise ValueError('Malformed CSV row')
                dns_rows += 1
                observed = {normalize(v) for v in row['dns.qry.name'].split(',') if normalize(v)}
                names.update(observed)
                for match in sorted(observed & indicators):
                    writer.writerow({'matched_domain': match, **row})
                    matches.add(match)
                    count += 1
        for filename, values in [('domains.txt', names), ('matches.txt', matches)]:
            (out / filename).write_text(''.join(v + '\n' for v in sorted(values)), encoding='utf-8')
        status.update(status='completed', outcome='matches' if matches else 'no_matches',
                      capture_sha256=before, dns_rows=dns_rows, unique_names=len(names),
                      matched_domains=len(matches), evidence_rows=count,
                      indicators=sorted(indicators))
        write_status(out, status)
        return status
    except BaseException as exc:
        status.update(status='failed', error=str(exc) or type(exc).__name__)
        write_status(out, status)
        raise

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('indicators', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    try:
        status = run(args.capture, args.indicators, args.output)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print('ERROR: ' + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(status, indent=2))
    print('A match does not establish malicious activity.')
    return 0

if __name__ == '__main__':
    sys.exit(main())
