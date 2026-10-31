"""The engine fails closed when the auditor stops attesting, so the attestation must be exact:
tolerant of a half-written file, never tolerant of a stale or violating auditor.
Regression: the first live runs tripped on a heartbeat read/rename race."""
import json
import tempfile
import time
import unittest
from pathlib import Path

from probe.audit import HEARTBEATS, VIOLATION, Attestation


def hb(path: Path, name: str, age: float = 0.0, **extra):
    (path / name).write_text(json.dumps({"t": time.time() - age, "violations": 0, **extra}), encoding="utf-8")


class AttestationTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.att = Attestation(self.dir)

    def test_missing_auditor_fails_closed(self):
        ok, why = self.att.check()
        self.assertFalse(ok)
        self.assertIn("missing", why)

    def test_fresh_heartbeat_passes(self):
        hb(self.dir, HEARTBEATS[0])
        self.assertTrue(self.att.check()[0])

    def test_a_half_written_file_does_not_trip_while_the_other_is_complete(self):
        hb(self.dir, HEARTBEATS[0])
        (self.dir / HEARTBEATS[1]).write_text('{"t": 17', encoding="utf-8")        # torn write
        self.assertTrue(self.att.check()[0])

    def test_a_single_unreadable_moment_is_tolerated_but_not_for_long(self):
        hb(self.dir, HEARTBEATS[0])
        self.assertTrue(self.att.check()[0])
        (self.dir / HEARTBEATS[0]).write_text("", encoding="utf-8")                # now nothing readable
        self.assertTrue(self.att.check()[0])                                       # last good one is still fresh
        self.att._last["t"] = time.time() - 10                                     # ...until it is not
        self.assertFalse(self.att.check()[0])

    def test_stale_heartbeat_fails_closed(self):
        hb(self.dir, HEARTBEATS[0], age=10)
        ok, why = self.att.check()
        self.assertFalse(ok)
        self.assertIn("stale", why)

    def test_the_newer_of_the_two_files_wins(self):
        hb(self.dir, HEARTBEATS[0], age=10)
        hb(self.dir, HEARTBEATS[1], age=0.1)
        self.assertTrue(self.att.check()[0])

    def test_any_recorded_violation_fails_closed(self):
        hb(self.dir, HEARTBEATS[0])
        (self.dir / VIOLATION).write_text("{}", encoding="utf-8")
        self.assertFalse(self.att.check()[0])

    def test_violations_counter_fails_closed(self):
        hb(self.dir, HEARTBEATS[0], violations=1)
        self.assertFalse(self.att.check()[0])


if __name__ == "__main__":
    unittest.main()
