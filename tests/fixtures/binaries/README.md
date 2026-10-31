# Binary fixtures

These are harmless placeholder files used only to exercise file-format
identification (`app/agents/binary_analysis/metadata.py`) without needing a
real compiled executable. They are never executed by anything in this
codebase.

- `sample.txt` — not a binary at all; used to test the "unrecognised format"
  path.
- Ghidra-dependent extraction (functions/strings/imports) is exercised via
  the synthetic fixture built into `ghidra_adapter.py` (`used_fixture=True`),
  not a real binary, since Ghidra is not installed in the dev/test
  environment.
