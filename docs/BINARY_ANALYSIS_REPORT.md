# Binary Analysis Agent: Ghidra integration report

Scope: 192.168.60.0/24, discovery/analysis stage only. No authentication attempt was made against any
service, Game Zone (TCP 8833) included, and nothing here expands the authorised scope.

## A. Headless Ghidra integration

Real, in-process Ghidra analysis via **PyGhidra** (`app/agents/binary_analysis/pyghidra_adapter.py`),
not the deprecated Jython `-postScript` path (Ghidra 12.x no longer runs that for plain scripts).

- Opens the acquired file through Ghidra's own loader; `program.getExecutableFormat()` gives the real
  format/architecture (used to distinguish supported vs. unsupported binaries, never assumed).
- Decompiles every non-thunk, non-external function; builds the real caller/callee graph from Ghidra's
  `ReferenceManager`.
- Collects every defined string, filtering out two sources of Ghidra-internal noise discovered during
  this work (see §F): section-header/string-table pseudo-addresses (`.shstrtab::...`), and the `u8"/u"/L"`
  C-string-literal prefix Ghidra's `getDefaultValueRepresentation()` attaches.
- A 180s worker-thread timeout (`GHIDRA_TIMEOUT_SECONDS`) bounds every analysis; a hang raises
  `ToolExecutionError`, it does not block the caller.
- `credential_recovery.find_validation_candidates()` flags functions that both compare input (`strcmp`/
  `strncmp`/`memcmp`/`strlen`) and emit ≥2 distinct output strings — a structural signal, not a keyword
  match — then `find_xor_key_schedule()` looks for a per-byte XOR-with-rotating-key pattern in the
  decompiled C: a `DAT_<addr>` lookup table, a key phrase, a modulus (literal `% N` or bitmask `& N-1`),
  an accumulator with a `strlen(...) == N` bound. **Every one of those pieces must be present in the code
  itself**; if any is missing, no schedule is reported — nothing is guessed.
- Static, fixed binary bytes only. A schedule derives its value from `read_memory()` on the same file; it
  never touches a value that depends on runtime input, network state, or anything outside the binary.

Verified against the real acquired KeyKeeper binary, sha256
`bbea9ba6cbe6facd9fd96d98cd99c9689d145d2c3c31cea6e44ca73461e48f1f`: `analysis_depth=full`, format and
language identified by Ghidra itself, one structurally-validated schedule recovered from `FUN_00401050`.

## B. Credential finding fields

Every `recovered_credential` finding (`app/agents/binary_analysis/discovered_artifact.py::_recover_credentials`)
carries, in `Weakness.context` — never the value itself:

| Field | Source |
|---|---|
| Source binary SHA-256 | `AcquiredBinary.sha256` |
| Function / code location | `function_name`, `function_address` |
| Evidence | the XOR schedule itself (array address, modulus, accumulator init/increment, length) |
| Extraction / recovery method | `"ghidra_decompiled_xor_key_schedule_recovery"` |
| Confidence & limitations | explicit strings — confidence is `medium` unless corroborated, `limitations` names what was and wasn't independently confirmed |
| Associated service | `service_correlation` — textual match against `correlation_terms` the Web Agent supplied, honestly `"unconfirmed"` when nothing corroborates |

Arbitrary strings are never reported as credentials: the separate, lower-confidence
`hardcoded_credential` category (regex/keyword heuristics in `static_analysis.py`) is kept distinct from
`recovered_credential`, which only fires on a structurally-validated schedule.

## C. Orchestrator integration

- `handle_discovered_binaries` (`app/orchestrator/nodes.py`) calls `store_secret()`
  (`app/core/protected_storage.py`) immediately on recovery — the value is written once, to a
  permission-restricted file, and never passed back up the call stack. Everything above that point only
  ever sees a `credential_ref`.
- A `BLOCKED` `AgentTask` (`task_type="authorised_credential_access"`,
  `TaskStatus.BLOCKED` added to `app/core/schemas.py`) is created for every recovered credential,
  id'd by `credential_ref` so it is created once. Nothing in the graph auto-transitions a `BLOCKED` task.
- The logged event and the `Finding`/`Weakness` both carry only the `credential_ref` and metadata —
  confirmed by direct inspection of the real end-to-end run's output (no plaintext anywhere) and by
  `test_transformed_derived_credential_xor_check`, which asserts the derived value string does not
  appear in the provenance record or the weakness's context/description.

## D. Subsequent discovery architecture

Documented in [`docs/DISCOVERY_ARCHITECTURE.md`](DISCOVERY_ARCHITECTURE.md): inventory merge-by-asset-id
(never overwritten), task-ledger upsert-by-id (never repeated), new devices get their own records (never
folded into the originating one), end-to-end provenance (service → binary → credential → any future
topology), and — the rule the rest exists to enforce — a recovered credential never auto-authorises
anything; only a separate, explicit, named approval can unblock its task.

## E. Testing

`tests/test_credential_recovery.py` (16 tests, all passing), plus the pre-existing
`tests/test_discovered_artifact_pipeline.py`. Three binaries compiled for real (MinGW gcc, `-O0 -static`,
genuine PE32+ executables, runtime-verified to accept/reject the right inputs before use):
`literal_check.exe` (plain embedded-string check), `xor_check.exe` (the transformed/derived case —
decodes to `Derived-Key-0042`), `decoy_strings.exe` (secret-shaped but unvalidated strings).

| Scenario | Covered by |
|---|---|
| Recoverable embedded credential | `test_recoverable_embedded_credential_literal_check` (real Ghidra run) |
| Transformed/derived credential | `test_transformed_derived_credential_xor_check` (real Ghidra run; round-trip derivation also unit-tested against the real KeyKeeper-shaped decompiled text) |
| Incorrect candidates | `test_incorrect_candidate_decoy_strings_produces_no_credential` |
| Missing analysis tool | `test_missing_analysis_tool_falls_back_to_real_raw_strings_never_a_fixture` |
| Unsupported architecture | `test_unsupported_architecture_degrades_to_raw_strings_not_a_crash` |
| Ghidra timeout | `test_ghidra_timeout_is_an_explicit_incomplete_result` |
| False-positive string extraction | `test_false_positive_section_metadata_strings_are_filtered` + the real end-to-end re-run in §F |
| Evidence provenance | `test_protected_storage_round_trips_and_never_echoes_the_value_in_provenance`, `test_unknown_credential_ref_raises_instead_of_returning_empty` |

**Full suite**: `python -m pytest tests -q` → **443 passed**, 0 failed.

## F. Real bugs found and fixed during this work

1. Ghidra's own section-header/string-table metadata (`.shstrtab::...`-style pseudo-addresses) was being
   read as program strings → filtered by address shape (`pyghidra_adapter.py`).
2. **Found by this stage's re-verification run, fixed just now**: Ghidra's `getDefaultValueRepresentation()`
   renders UTF-8 string literals with a `u8"..."` C-prefix; stripping only the quote characters left the
   prefix attached (`u8"GLIBC_2.34`), which let six dynamic-linker-noise strings (`strlen`,
   `__libc_start_main`, `libc.so.6`, `GLIBC_2.2.5`, `GLIBC_2.34`, `__gmon_start__`) slip past the existing
   noise filter and get reported as low-confidence `hardcoded_credential` hits. Fixed by matching the
   actual literal content with a small regex instead of a blind `.strip('"')`. Re-run against the real
   KeyKeeper binary after the fix: **1 weakness total** (the genuine recovered credential), zero noise.

## Remaining limitations

- **`Weakness.context["service_correlation"]` is textual, not a structured `service_id` link.** The
  finding names the correlating terms it matched, but does not yet carry a formal foreign key to the
  `NetworkGraph` service record. Section C's "associate the finding with... the relevant service" is
  satisfied in substance (the text names the service) but not as a structured join.
- **PyGhidra's JVM startup (`jpype.startJVM`) intermittently logs a Windows "fatal exception: access
  violation" during its own native initialization**, observed consistently on this machine/Java build but
  never affecting the actual analysis result (every run that logged it still produced correct output,
  cross-checked against an independent manual derivation). Treated as an environment-level JPype/JVM
  startup quirk, not a defect in this integration; worth a clean rerun on a different JDK build before
  relying on it outside this session.
- **Feeding a non-executable file through the real PyGhidra loader was observed once to trigger a native
  access violation** in `pyghidra/core.py::_setup_project` rather than a clean Python exception. The
  "unsupported architecture" test was changed to pin the *required contract* (clean fallback, no crash)
  via a mocked failure rather than keep re-triggering that native path on every test run. If an
  attacker-controlled file is ever handed to this pipeline unsanitised, this is a real crash/DoS surface
  in PyGhidra itself worth isolating (e.g. a subprocess boundary) before doing so.
- Section A's distinguishing of "statically recoverable" vs. "dynamically generated/externally supplied"
  is enforced by requiring every schedule input to be a fixed constant found in the decompiled text and
  fixed bytes read from the binary itself — but this only covers the one structural pattern implemented
  (fixed-length, per-byte XOR with a rotating literal key). A credential derived through a different
  transform (e.g. a checksum, a different cipher, a runtime-seeded value) would not be found; the detector
  does not claim completeness, only soundness for what it does report.
- No credential was submitted anywhere; Game Zone (port 8833) was not contacted. The recovered credential
  sits behind `credential_ref = CRED-493E7B534CC5478A`, referenced by a `BLOCKED`
  `authorised_credential_access` task — nothing in this stage acts on it further.
