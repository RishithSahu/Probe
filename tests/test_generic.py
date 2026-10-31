"""The tool must be generic: nothing in the product code, docs or templates may be specific to one network, event or
organisation. This fails the build if site-specific strings creep back in (sample data in tests/ is exempt).
Run: python -m unittest discover -s tests -v"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FORBIDDEN = {
    r"192\.168\.60\.": "a specific lab address range (use a neutral example)",
    r"(?i)mitigata": "an organisation name",
    r"(?i)hackathon": "an event name",
    r"(?i)organi[sz]ers?\b": "event-specific wording (say 'network owner')",
    r"(?i)cyberforge": "an event name",
}
SOURCES = [*ROOT.glob("probe/**/*.py"), *ROOT.glob("probe/**/*.html"), *ROOT.glob("docs/*.md"), ROOT / "README.md",
           *ROOT.glob("enforce/*"), ROOT / "requirements.txt", ROOT / "probe-scope.example.txt"]


class NothingIsSiteSpecific(unittest.TestCase):
    def test_no_site_specific_strings_in_product_code_docs_or_templates(self):
        offenders = []
        for path in SOURCES:
            if "__pycache__" in path.parts or not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            for pattern, why in FORBIDDEN.items():
                for m in re.finditer(pattern, text):
                    line = text.count("\n", 0, m.start()) + 1
                    offenders.append(f"{path.relative_to(ROOT)}:{line}: {m.group(0)!r} ({why})")
        self.assertEqual([], offenders, "site-specific content found:\n" + "\n".join(offenders))

    def test_the_scope_is_never_hard_coded_it_comes_from_the_operator(self):
        from probe.cli import SCOPE_FILE
        self.assertEqual("probe-scope.txt", str(SCOPE_FILE))
        self.assertFalse((ROOT / "probe-scope.example.txt").read_text().count("192.168.60"))

    def test_probe_selection_is_data_driven_not_hand_tuned_to_a_network(self):
        from probe.discovery import tiers
        from probe.engine import Engine
        from probe.scope import ScopeGuard
        from probe.store import Store
        e = Engine(ScopeGuard(["10.20.30.0/24"]), Store(":memory:"), None)
        self.assertTrue(set(tiers.top_tcp_ports(10)) <= set(e.cheap_ports))   # the common-ports set comes from nmap's ranking

    def test_the_same_engine_works_for_any_private_range(self):
        from probe import selftest
        for scope in (["10.20.30.0/24"], ["172.20.0.0/22"], ["192.168.7.0/24", "10.99.0.0/28"]):
            self.assertEqual([], selftest.run(scope), scope)


if __name__ == "__main__":
    unittest.main()
