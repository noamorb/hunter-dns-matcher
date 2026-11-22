# Hunter — Offline DNS Domain Matcher

A cybersecurity lab project by **Noam Orbach** ([noamorb](https://github.com/noamorb)).

Hunter is a Python and Bash tool that uses TShark to match DNS names in packet captures against a domain list. It exports the matching frame numbers, addresses and DNS fields to CSV so analysts can inspect the original evidence.

## What I verified in Kali Linux

- Ran 10 automated tests and checked the tool on a lab PCAP. The tests use mocked TShark output. The lab run used TShark on a capture.
- Found one exact match across seven unique DNS names. Frame 225 contained a DNS response with two IPv4 addresses, both preserved in a single CSV field.
- Used the DNS result in a [Windows forensics case study](https://github.com/noamorb/windows-forensics-case-study) to check an IP match against a network artifact recovered from memory.

See the [validation record](VALIDATION.md) and [sample CSV](examples/match_evidence.csv) for the evidence.

## Requirements and quick start

Linux, Python 3.8+ and TShark on PATH. No sudo, network calls or Python packages required.

```bash
bash hunter.sh /path/to/packets.pcap test_indicators.txt results
python3 -m unittest -v
```

Replace `/path/to/packets.pcap` with your own capture and choose a new output directory each run. The supplied indicators are test data,
not a threat-intelligence feed; games.samsclass.info is not labeled malicious.

## Example result

In the Kali lab run, Hunter reported seven unique DNS names and one exact match. The matching row records frame 225 and preserves both IPv4 answers in a single CSV field. See the [sample output](examples/match_evidence.csv) for the actual row and the [validation notes](VALIDATION.md) for the test scope.

## Workflow

1. Validate the indicator list and capture readability before extraction.
2. Refuse existing output directories.
3. Hash the capture, extract DNS with TShark, and verify the capture hash again.
4. Normalize case and one trailing dot; match complete names only.
5. Save evidence and a final status.

Only ASCII/punycode domain names are accepted. Blank lines and lines starting
with # are ignored. Subdomains are NOT matched implicitly. A response's question
name is included, even when the original query is absent from the capture.

## Outputs

- `status.json`: running, completed or failed. Completed runs also distinguish
  matches from no_matches and report counts plus capture SHA-256.
- `dns_evidence.csv`: DNS frame fields including IPv4/IPv6 endpoints and A/AAAA fields.
- `match_evidence.csv`: matching domain plus complete frame evidence.
- `domains.txt`, `matches.txt`: sorted unique names.
- `tshark.log`: extraction warnings or errors.

Exit 0 means successful analysis, including zero matches. Exit 1 means an error;
argument parsing may return 2. Failures before output creation print to stderr.
After output creation, failures leave diagnostic files and failed status when
writing remains possible. Abrupt termination/power loss can leave running status:
only completed status authorizes treating the results as complete.

## Limits and interpretation

This is not an IDS, malware detector, or proof of browsing. DNS presence alone
does not establish malicious activity. It inspects dns.qry.name only, not every
name in answer records, HTTP Host, TLS SNI or encrypted DNS. Returned addresses
are preserved as frame-level evidence, not guaranteed individual domain/address
relationships in unusual multi-question messages. IPv6 fields are exported but
real IPv6 capture integration has not yet been validated. CSV fields are quoted
by a CSV writer; open evidence as text or with automatic spreadsheet formulas disabled.

The original user capture has identical timestamps, so no timing/rate conclusions
are justified. Its 7 DNS names and match at frame 225 were verified in v1.
The original capture is not distributed here. Version 2 was also run successfully
by Noam in Kali on 2026-11-15. See VALIDATION.md for the reported evidence and
the distinction between real-capture validation and mocked tests.

## Tests and provenance

`test_hunter.py` contains 10 tests with mocked TShark output: matching and CSV
preservation, IPv6-field preservation, no DNS, no matches, absent capture,
empty/invalid indicators, existing output protection, extraction failure,
malformed CSV, and capture changes (some covered together in one test).
These verify application logic, not TShark's ability to decode a PCAP.
`test-results.txt` records the development run: all 10 passed.

When changing the code, rerun the tests and a real-capture check. Do not
distribute captures without permission.

## Repository layout

- `hunter.py`: validation, extraction, matching and reporting.
- `hunter.sh`: Bash entry point.
- `test_hunter.py`: repeatable isolated tests.
- `VALIDATION.md`: verification scope and limitations.
- `examples/`: example evidence transcribed from the reported Kali run.

## Attribution

Noam Orbach ran the lab analysis and validated the results in Kali Linux. Hunter grew out of a John Bryce course project. AI assisted with implementation and review of the portfolio version.
