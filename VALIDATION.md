# Validation record — 2026-11-15

## Automated tests

All 10 unittest tests passed in the development environment and in Noam's Kali
VM (the latter reported 0.013 seconds). TShark is mocked in these tests: they
validate application behavior, not the real decoder. See test_hunter.py and
test-results.txt. Python and Bash source were also syntax checked.

## Real capture integration (user-executed)

Noam ran version 2 in Kali against his local packets.pcap and supplied the console
summary and evidence row. The run reported:

- status: completed; outcome: matches
- DNS rows: 7; unique names: 7
- matched domains: 1; evidence rows: 1
- matching domain: games.samsclass.info; frame: 225
- DNS response: 8.8.8.8 to 192.168.225.129
- A fields: 104.28.16.29 and 104.28.17.29
- tshark.log displayed no content
- capture SHA-256: 7d71f03f8e7068da2a7353018f89fa7a8dd864f79313108f8dbab39230bfd10a

The examples CSV is transcribed from that console output, not an independently
rerun capture. The original capture was not supplied to the reviewer and is not
included. The domain is a synthetic matching target, not a malicious-domain claim.

## Remaining limits

Real IPv6 traffic, larger captures, and varied capture formats have not been
integration-tested. Captures without DNS are covered by mocked output only.
The original capture has unusable identical timestamps; no timeline or rate
analysis is claimed. Domain occurrence is not proof of compromise or browsing.
