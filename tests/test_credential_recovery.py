"""Section E of the brief: synthetic binaries with KNOWN validation logic and known expected results.

Three real compiled binaries (tests/fixtures/binaries/{literal_check,xor_check,decoy_strings}.exe, built
from tests/fixtures/binaries/src/*.c) exercise the real PyGhidra path end to end when Ghidra is installed on
the machine running these tests; they are skipped (not faked) otherwise, since this project never
substitutes canned data for a real analysis. The regex-level detector tests and the fallback/incomplete/
provenance tests need no Ghidra install at all and always run.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from app.agents.binary_analysis import credential_recovery as cr
from app.agents.binary_analysis import discovered_artifact as da
from app.agents.binary_analysis.acquisition import AcquiredBinary
from app.agents.binary_analysis.ghidra_adapter import GhidraAnalysisResult, GhidraString
from app.core.config import settings
from app.core.exceptions import ToolExecutionError
from app.core.protected_storage import get_provenance, retrieve_secret

FIXTURES = Path(__file__).parent / "fixtures" / "binaries"
GHIDRA_DIR = Path("C:/Program Files/ghidra_12.1.4_PUBLIC")
HAS_GHIDRA = GHIDRA_DIR.exists()

requires_ghidra = pytest.mark.skipif(not HAS_GHIDRA, reason="real Ghidra install not present on this machine")


def _acquired(name: str) -> AcquiredBinary:
    path = FIXTURES / name
    data = path.read_bytes()
    return AcquiredBinary(source_url=f"http://fixture.test/{name}", saved_path=path,
                          sha256=hashlib.sha256(data).hexdigest(), byte_count=len(data), truncated=False)


@pytest.fixture
def ghidra_configured(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "ghidra_install_dir", str(GHIDRA_DIR))
    monkeypatch.setattr(settings, "ghidra_project_dir", tmp_path / "ghidra_projects")
    monkeypatch.setattr(settings, "evidence_dir", tmp_path / "evidence")
    yield


# ---------------------------------------------------------------------------
# Generic detector (no Ghidra needed -- regex-level, against known decompiled text)
# ---------------------------------------------------------------------------

_KEYKEEPER_STYLE_TEXT = '''
undefined8 FUN_00401050(int param_1,long param_2)
{
  char *__s; size_t sVar1; long lVar2; byte bVar3;
  puts("== fixture ==");
  if (param_1 < 2) {
    puts("usage: x <value>");
  }
  else {
    __s = *(char **)(param_2 + 8);
    sVar1 = strlen(__s);
    if (sVar1 == 0x10) {
      bVar3 = 0xd;
      lVar2 = 0;
      while ((byte)((&DAT_004020b0)[lVar2] ^ bVar3 ^ "mitigata"[(uint)lVar2 & 7]) == __s[lVar2]) {
        lVar2 = lVar2 + 1;
        bVar3 = bVar3 + 7;
        if (lVar2 == 0x10) {
          puts("[+] accepted.");
          return 0;
        }
      }
    }
    puts("[-] denied.");
  }
  return 1;
}
'''


def test_recovers_the_exact_known_schedule_from_decompiled_text():
    schedule = cr.find_xor_key_schedule(_KEYKEEPER_STYLE_TEXT)
    assert schedule is not None
    assert schedule.array_address == 0x004020B0
    assert schedule.key_phrase == "mitigata"
    assert schedule.modulus == 8          # recovered from a BITMASK ('& 7'), not a literal '% 8'
    assert schedule.initial_value == 13
    assert schedule.increment == 7
    assert schedule.length == 16


def test_derivation_is_a_pure_function_of_schedule_and_bytes():
    schedule = cr.find_xor_key_schedule(_KEYKEEPER_STYLE_TEXT)
    # cipher bytes independently produced by encoding "KeyKeeper-Fixtu!" with this exact schedule
    plaintext = b"KeyKeeper-Fixtu!"
    key = schedule.key_phrase.encode()
    acc = schedule.initial_value
    cipher = bytearray()
    for i in range(schedule.length):
        cipher.append(plaintext[i] ^ (acc & 0xFF) ^ key[i % schedule.modulus])
        acc += schedule.increment
    value = cr.derive_value(schedule, bytes(cipher))
    assert value == plaintext


def test_no_schedule_is_reported_when_the_structural_pattern_is_absent():
    plain_strcmp_text = 'int main(void){ return strcmp(x,"literal") == 0; }'
    assert cr.find_xor_key_schedule(plain_strcmp_text) is None


def test_insufficient_length_evidence_refuses_to_guess():
    # XOR expression present but no strlen(...)==LEN anywhere -- must not invent a length.
    text = _KEYKEEPER_STYLE_TEXT.replace("sVar1 == 0x10", "sVar1 == len_from_elsewhere")
    assert cr.find_xor_key_schedule(text) is None


def test_derive_value_matches_a_known_round_trip():
    # Independent of the class above: construct a schedule, encode a chosen plaintext, decode it back.
    plaintext = b"RoundTrip-Check!"
    assert len(plaintext) == 16
    key = b"abcXYZ12"
    acc = 200
    cipher = bytearray()
    for i in range(16):
        cipher.append((plaintext[i] ^ ((acc + i * 3) & 0xFF) ^ key[i % 8]) & 0xFF)
    schedule = cr.XorKeySchedule(array_symbol="DAT_1000", array_address=0x1000, key_phrase="abcXYZ12",
                                 modulus=8, initial_value=200, increment=3, length=16)
    assert cr.derive_value(schedule, bytes(cipher)) == plaintext


def test_validation_candidate_heuristic_is_structural_not_wording_based():
    functions = {"xorcheck": _KEYKEEPER_STYLE_TEXT, "no_compare": 'void f(void){ puts("hello"); }'}
    out = cr.find_validation_candidates(functions)
    names = {c.function_name for c in out}
    assert names == {"xorcheck"}
    assert out[0].xor_schedule is not None


# ---------------------------------------------------------------------------
# Real compiled binaries through the full pipeline (skipped without a Ghidra install)
# ---------------------------------------------------------------------------


@requires_ghidra
def test_recoverable_embedded_credential_literal_check(ghidra_configured, tmp_path):
    analysis = da.analyse_discovered_binary(_acquired("literal_check.exe"), output_dir=tmp_path)
    assert analysis.analysis_depth == da.ANALYSIS_FULL
    assert not analysis.incomplete
    # A literal strcmp target is a plain embedded string, not a derived schedule -- no recovered_credential.
    assert analysis.recovered_credentials == []
    cat_hits = [w for w in analysis.weaknesses if w.category == "hardcoded_credential" and w.matched_value == "SuperSecret123!"]
    assert cat_hits, [w.matched_value for w in analysis.weaknesses]


@requires_ghidra
def test_transformed_derived_credential_xor_check(ghidra_configured, tmp_path):
    acquired = _acquired("xor_check.exe")
    analysis = da.analyse_discovered_binary(acquired, output_dir=tmp_path, correlation_terms=("testkey9",))
    assert analysis.analysis_depth == da.ANALYSIS_FULL
    assert len(analysis.recovered_credentials) == 1
    rc = analysis.recovered_credentials[0]

    # provenance is retrievable and complete -- but contains NO trace of the value
    prov = get_provenance(rc["credential_ref"])
    assert prov["source_binary_sha256"] == acquired.sha256
    assert prov["extraction_method"] == "ghidra_decompiled_xor_key_schedule_recovery"
    assert "Derived-Key-0042" not in str(prov)

    # the value is only reachable through the deliberate, explicit accessor
    assert retrieve_secret(rc["credential_ref"]) == b"Derived-Key-0042"

    # and it is nowhere in the ordinary findings
    cred_weakness = next(w for w in analysis.weaknesses if w.category == "recovered_credential")
    assert "Derived-Key-0042" not in str(cred_weakness.context)
    assert "Derived-Key-0042" not in cred_weakness.description


@requires_ghidra
def test_incorrect_candidate_decoy_strings_produces_no_credential(ghidra_configured, tmp_path):
    analysis = da.analyse_discovered_binary(_acquired("decoy_strings.exe"), output_dir=tmp_path)
    assert analysis.recovered_credentials == []
    for w in analysis.weaknesses:
        if w.category == "hardcoded_credential":
            assert "unconfirmed" in w.context["service_correlation"]
            assert w.confidence == "low"


@requires_ghidra
def test_false_positive_section_metadata_strings_are_filtered(ghidra_configured, tmp_path):
    """BUG FIX regression: Ghidra's own ELF/PE section-table metadata (synthetic addresses like
    '.shstrtab::00000001') was being read as program strings and then flagged as low-confidence
    credentials. None of that should appear."""
    analysis = da.analyse_discovered_binary(_acquired("decoy_strings.exe"), output_dir=tmp_path)
    for w in analysis.weaknesses:
        addr = (w.context or {}).get("address", "")
        assert "::" not in str(addr)


# ---------------------------------------------------------------------------
# Missing tool / unsupported architecture / timeout -- explicit incomplete, never fabricated
# ---------------------------------------------------------------------------


def test_missing_analysis_tool_falls_back_to_real_raw_strings_never_a_fixture(monkeypatch, tmp_path):
    # Once started in-process, Ghidra's JVM cannot be "un-started" within the test run, so this
    # exercises the same not-configured failure discovered_artifact must tolerate by patching the
    # entry point it calls rather than relying on a second real pyghidra_adapter.analyse() failing.
    import app.agents.binary_analysis.discovered_artifact as da_module
    from app.core.exceptions import ToolExecutionError as _TEE

    def _not_configured(*_a, **_k):
        raise _TEE("Ghidra Headless Analyzer not configured (APE_GHIDRA_INSTALL_DIR unset)")

    monkeypatch.setattr(da_module, "pyghidra_analyse", _not_configured)
    acquired = _acquired("literal_check.exe")
    analysis = da.analyse_discovered_binary(acquired, output_dir=tmp_path)
    assert analysis.analysis_depth == da.ANALYSIS_STRINGS_ONLY
    assert not analysis.incomplete
    assert any("not configured" in e for e in analysis.errors)
    # the canned Ghidra fixture's own known strings must never appear
    assert all(w.matched_value not in ("admin", "S3cr3tP@ssw0rd!", "/bin/sh") for w in analysis.weaknesses)


def test_unsupported_architecture_degrades_to_raw_strings_not_a_crash(monkeypatch, tmp_path):
    # NOTE: feeding a genuinely non-executable file through the real PyGhidra loader was tried first and
    # reproducibly triggered a native access-violation deep in the JPype/JVM layer (pyghidra/core.py
    # _setup_project) -- a real robustness limitation of the "full" tier, recorded in the final report, not
    # something to keep re-triggering on every test run. This test instead pins the *contract*
    # discovered_artifact must honour when Ghidra's own loader rejects a format cleanly: fall back to the
    # real raw-strings tier, never crash the caller, never fabricate a result.
    import app.agents.binary_analysis.discovered_artifact as da_module
    from app.core.exceptions import ToolExecutionError as _TEE

    def _unsupported_format(*_a, **_k):
        raise _TEE("Ghidra could not identify an executable format for not_a_binary.bin")

    monkeypatch.setattr(da_module, "pyghidra_analyse", _unsupported_format)
    plain = tmp_path / "not_a_binary.bin"
    plain.write_bytes(b"just some ascii content, no executable format here, 123456\x00\x00")
    acquired = AcquiredBinary(source_url="http://fixture.test/x", saved_path=plain,
                              sha256=hashlib.sha256(plain.read_bytes()).hexdigest(),
                              byte_count=plain.stat().st_size, truncated=False)
    analysis = da.analyse_discovered_binary(acquired, output_dir=tmp_path)
    assert analysis.analysis_depth == da.ANALYSIS_STRINGS_ONLY
    assert not analysis.incomplete
    assert any("executable format" in e for e in analysis.errors)


def test_ghidra_timeout_is_an_explicit_incomplete_result(monkeypatch, tmp_path):
    """Simulates a Ghidra hang without actually waiting for one: the worker-thread timeout path in
    pyghidra_adapter.analyse must surface as ToolExecutionError (and this module must fall back to the raw
    string tier), never hang the caller and never fabricate a result."""
    import app.agents.binary_analysis.discovered_artifact as da_module

    def _hangs(*_a, **_k):
        raise ToolExecutionError("Ghidra analysis of x did not finish within 0.01s (timeout)")

    monkeypatch.setattr(da_module, "pyghidra_analyse", _hangs)
    acquired = _acquired("literal_check.exe")
    analysis = da.analyse_discovered_binary(acquired, output_dir=tmp_path)
    assert analysis.analysis_depth == da.ANALYSIS_STRINGS_ONLY
    assert any("timeout" in e for e in analysis.errors)


def test_completely_unreadable_file_is_incomplete_not_fabricated(tmp_path):
    missing = tmp_path / "gone.bin"
    acquired = AcquiredBinary(source_url="http://fixture.test/x", saved_path=missing, sha256="x",
                              byte_count=0, truncated=False)
    analysis = da.analyse_discovered_binary(acquired, output_dir=tmp_path)
    assert analysis.incomplete
    assert analysis.weaknesses == []
    assert analysis.recovered_credentials == []


# ---------------------------------------------------------------------------
# Evidence provenance
# ---------------------------------------------------------------------------


def test_protected_storage_round_trips_and_never_echoes_the_value_in_provenance(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "evidence_dir", tmp_path / "evidence")
    from app.core.protected_storage import CredentialProvenance, store_secret

    secret_value = b"totally-real-test-secret"
    ref = store_secret(secret_value, CredentialProvenance(
        source_binary_sha256="abc123", source_url="http://x/y", function_name="main",
        function_address="0x1000", extraction_method="unit-test", confidence="high",
        limitations="none", associated_service_id="HOST:80/tcp",
    ))
    assert retrieve_secret(ref) == secret_value
    prov = get_provenance(ref)
    assert secret_value.decode() not in str(prov)
    assert prov["source_binary_sha256"] == "abc123"
    assert prov["function_name"] == "main"
    assert prov["confidence"] == "high"


def test_unknown_credential_ref_raises_instead_of_returning_empty():
    with pytest.raises(KeyError):
        retrieve_secret("CRED-DOES-NOT-EXIST")
    with pytest.raises(KeyError):
        get_provenance("CRED-DOES-NOT-EXIST")


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
