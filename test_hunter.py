"""Application tests with mocked TShark; no claim of real capture parsing."""
import csv
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import hunter

class HunterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.capture = self.root / 'capture with spaces.pcap'
        self.capture.write_bytes(b'test fixture placeholder')
        self.indicators = self.root / 'indicators.txt'
        self.indicators.write_text('GAMES.SAMSCLASS.INFO.\nsamsclass.info\nnot-present.invalid\n')
        self.out = self.root / 'result'
        self.rows = []
        self.which = patch('hunter.shutil.which', return_value='/fake/tshark').start()
        self.proc = patch('hunter.subprocess.run', side_effect=self.extract).start()
        self.addCleanup(patch.stopall)
    def extract(self, command, stdout, stderr, check):
        writer = csv.DictWriter(stdout, fieldnames=hunter.FIELDS)
        writer.writeheader()
        writer.writerows(self.rows)
    def row(self, **values):
        row = dict.fromkeys(hunter.FIELDS, '')
        row.update(values)
        return row
    def run_tool(self):
        return hunter.run(self.capture, self.indicators, self.out)
    def test_match_csv_and_ipv6(self):
        self.rows = [self.row(**{'frame.number':'225', 'dns.qry.name':'games.samsclass.info',
            'dns.a':'104.28.16.29,104.28.17.29', 'ipv6.src':'2001:db8::1', 'dns.aaaa':'2001:db8::2'})]
        status = self.run_tool()
        self.assertEqual(status['matched_domains'], 1)
        self.assertEqual((self.out/'matches.txt').read_text(), 'games.samsclass.info\n')
        with (self.out/'match_evidence.csv').open() as f:
            row = next(csv.DictReader(f))
        self.assertEqual(row['dns.a'], '104.28.16.29,104.28.17.29')
        self.assertEqual(row['dns.aaaa'], '2001:db8::2')
    def test_no_dns(self):
        result = self.run_tool()
        self.assertEqual((result['outcome'], result['dns_rows']), ('no_matches', 0))
    def test_no_matching_domain(self):
        self.rows = [self.row(**{'dns.qry.name':'example.org'})]
        self.assertEqual(self.run_tool()['outcome'], 'no_matches')
    def test_missing_capture(self):
        self.capture.unlink()
        with self.assertRaises(OSError): self.run_tool()
        self.proc.assert_not_called()
        self.assertFalse(self.out.exists())
    def test_empty_indicators(self):
        self.indicators.write_text('# comment\n')
        with self.assertRaises(ValueError): self.run_tool()
        self.proc.assert_not_called()
        self.assertFalse(self.out.exists())
    def test_invalid_indicator(self):
        self.indicators.write_text('https://example.org\n')
        with self.assertRaises(ValueError): self.run_tool()
        self.proc.assert_not_called()
    def test_existing_output(self):
        self.out.mkdir()
        (self.out/'keep.txt').write_text('unchanged')
        with self.assertRaises(FileExistsError): self.run_tool()
        self.assertEqual((self.out/'keep.txt').read_text(), 'unchanged')
        self.proc.assert_not_called()
    def test_tshark_failure(self):
        self.proc.side_effect = subprocess.CalledProcessError(2, 'tshark')
        with self.assertRaises(subprocess.CalledProcessError): self.run_tool()
        self.assertEqual(json.loads((self.out/'status.json').read_text())['status'], 'failed')
    def test_bad_csv(self):
        self.proc.side_effect = lambda *a, **kw: kw['stdout'].write('wrong,columns\n')
        with self.assertRaises(ValueError): self.run_tool()
        self.assertEqual(json.loads((self.out/'status.json').read_text())['status'], 'failed')
    def test_changed_capture(self):
        with patch('hunter.digest', side_effect=['before', 'after']):
            with self.assertRaises(ValueError): self.run_tool()
        self.assertEqual(json.loads((self.out/'status.json').read_text())['status'], 'failed')

if __name__ == '__main__': unittest.main()
