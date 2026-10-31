"""Generic recovery of a statically-derived (XOR/rotating-key-transformed) credential from a Ghidra-
decompiled function, plus a generic structural heuristic for flagging which functions are worth examining
this way.

Nothing here is specific to any one binary: every constant (array address, key phrase, initial value,
increment, required length) is EXTRACTED from the decompiled C text and the binary's own bytes, never
assumed or hardcoded. If the structural pattern this module looks for is absent, it reports nothing --
never a guess. This distinguishes a "statically recoverable" credential (point 9 of the brief) from one
that is generated at runtime or supplied externally: if the schedule's inputs are not all present as fixed
bytes in the binary itself, derivation is refused.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# "strlen(...)" followed, within a bounded distance, by a comparison against a constant -- the loop's trip
# count. The result is usually assigned to a temporary first (`sVar2 = strlen(x); if (sVar2 == 16)`), so the
# gap is matched generically (bounded length, not excluding ';'/'{') rather than assuming the two sit in one
# statement.
_LEN_RE = re.compile(r"strlen\([^)]{0,80}\).{0,60}?==\s*(0x[0-9a-fA-F]+|\d+)", re.DOTALL)

# (&SOME_DAT_SYMBOL)[i] ^ acc ^ "key phrase"[i % N]  -- Ghidra's own default naming for an anonymous data
# symbol is DAT_<hex address>, which is what makes the address recoverable without a symbol table lookup:
# the address IS the name. The key-index expression is matched for BOTH a true modulo (`i % N`) and the
# equivalent power-of-two bitmask Ghidra/GCC often emit instead (`(uint)i & (N-1)`).
_XOR_EXPR_RE = re.compile(
    r'\(&(?P<array>\w*DAT_[0-9A-Fa-f]+)\)\[(?P<idx>\w+)\]\s*\^\s*(?P<acc>\w+)\s*\^\s*'
    r'"(?P<key>[^"]*)"\[\s*(?:\([^)]*\)\s*)?(?P=idx)\s*(?P<modop>%|&)\s*(?P<mod>\d+)\s*\]'
)
_ADDR_SUFFIX_RE = re.compile(r"DAT_([0-9A-Fa-f]+)$")


@dataclass
class XorKeySchedule:
    array_symbol: str
    array_address: int
    key_phrase: str
    modulus: int
    initial_value: int
    increment: int
    length: int

    def as_context(self) -> dict:
        """Everything EXCEPT the derived plaintext -- safe to attach to an ordinary Finding/Evidence; the
        schedule describes the METHOD, not the secret."""
        return {
            "array_symbol": self.array_symbol, "array_address": hex(self.array_address),
            "key_phrase_length": len(self.key_phrase), "modulus": self.modulus,
            "initial_value": self.initial_value, "increment": self.increment, "length": self.length,
        }


def find_xor_key_schedule(decompiled_c: str) -> XorKeySchedule | None:
    """Looks for `(&SYM)[i] ^ acc ^ "key"[i % N or i & (N-1)]`, immediately compared (either direction)
    against `input[i]`, inside a loop whose trip count matches an earlier `strlen(...) == LEN` check, with
    `acc` initialised once and incremented by a fixed amount somewhere in the function. Returns None (never
    a guess) if any required piece is missing."""
    for xor_match in _XOR_EXPR_RE.finditer(decompiled_c):
        idx = xor_match.group("idx")
        tail = decompiled_c[xor_match.end():xor_match.end() + 80]
        # The XOR expression must be compared against the caller-supplied input at the SAME index, with
        # either operator (a "while equal, keep going" loop and an "if different, reject" loop are both
        # legitimate shapes for the same check) -- checked in a short window right after the expression.
        if not re.match(r"^\)?\s*(==|!=)\s*\w+\s*\[\s*" + re.escape(idx) + r"\s*\]", tail):
            continue
        array_symbol, acc, key, modop, mod = xor_match.group("array", "acc", "key", "modop", "mod")
        modulus = int(mod) + 1 if modop == "&" else int(mod)

        addr_match = _ADDR_SUFFIX_RE.search(array_symbol)
        if not addr_match:
            continue
        array_address = int(addr_match.group(1), 16)

        len_match = _LEN_RE.search(decompiled_c)
        if not len_match:
            continue
        length = int(len_match.group(1), 0)
        if length <= 0 or length > 4096:
            continue

        init_match = re.search(rf"\b{re.escape(acc)}\s*=\s*(0x[0-9a-fA-F]+|\d+)\s*;", decompiled_c)
        incr_match = re.search(rf"\b{re.escape(acc)}\s*=\s*{re.escape(acc)}\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*;",
                               decompiled_c)
        if not init_match or not incr_match:
            continue

        return XorKeySchedule(
            array_symbol=array_symbol, array_address=array_address, key_phrase=key, modulus=modulus,
            initial_value=int(init_match.group(1), 0) & 0xFF, increment=int(incr_match.group(1), 0) & 0xFF,
            length=length,
        )
    return None


def derive_value(schedule: XorKeySchedule, memory_bytes: bytes) -> bytes:
    """`memory_bytes` must be exactly (or more than) `schedule.length` bytes read from `schedule.array_address`
    in the SAME binary this schedule was extracted from -- never substituted from anywhere else. Every input
    (the array bytes, the key phrase, the accumulator schedule) is a fixed value inside the binary; nothing
    here is generated at runtime or supplied externally, which is what makes this a legitimate STATIC
    recovery rather than a guess."""
    if len(memory_bytes) < schedule.length:
        raise ValueError("not enough memory bytes supplied for this schedule's length")
    key = schedule.key_phrase.encode("latin-1") if schedule.key_phrase else b""
    out = bytearray()
    acc = schedule.initial_value & 0xFF
    for i in range(schedule.length):
        k = key[i % schedule.modulus] if key and schedule.modulus else 0
        out.append((memory_bytes[i] ^ acc ^ k) & 0xFF)
        acc = (acc + schedule.increment) & 0xFF
    return bytes(out)


# ---- generic "is this function worth looking at" heuristic --------------------------------------------

_COMPARE_CALLS = ("strcmp", "strncmp", "memcmp", "strlen")
_OUTPUT_CALLS_RE = re.compile(r'\b(?:puts|printf|fprintf)\s*\(\s*(?:\w+\s*,\s*)?"([^"]*)"')
_LITERAL_STRCMP_RE = re.compile(r'\bstrn?cmp\s*\([^,]+,\s*"[^"]+"\s*(?:,[^)]+)?\)')


@dataclass
class ValidationCandidate:
    function_name: str
    reason: str
    has_literal_compare: bool
    xor_schedule: XorKeySchedule | None


def find_validation_candidates(functions: dict[str, str]) -> list[ValidationCandidate]:
    """`functions`: {name: decompiled_c_text}. Flags a function as a candidate input-validation/credential
    check using only STRUCTURE: it compares a value (strcmp/strncmp/memcmp/strlen) AND has at least two
    distinct literal output strings (read as an accept path and a reject path) -- never keyed to specific
    wording like "password" or "passkey", so it generalises across unrelated binaries. A function that
    merely contains a secret-shaped string without this structure is not a candidate."""
    out = []
    for name, text in functions.items():
        if not any(call + "(" in text for call in _COMPARE_CALLS):
            continue
        outputs = set(_OUTPUT_CALLS_RE.findall(text))
        if len(outputs) < 2:
            continue
        out.append(ValidationCandidate(
            function_name=name,
            reason=f"compares an input value and has {len(outputs)} distinct output strings "
                   "(consistent with an accept path and a reject path)",
            has_literal_compare=bool(_LITERAL_STRCMP_RE.search(text)),
            xor_schedule=find_xor_key_schedule(text),
        ))
    return out
