"""Stage C: static weakness identification.

Pure, deterministic pattern-matching over the metadata (Stage A) and Ghidra
output (Stage B) already collected — no new tool invocations happen here,
and the binary is never executed. Every detector produces a `Weakness` with
enough context (the matched string/function, its address where known) to be
independently reviewed; nothing here claims a function is exploitable merely
because it exists, per the PRD's explicit requirement.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.agents.binary_analysis.ghidra_adapter import GhidraAnalysisResult
from app.agents.binary_analysis.metadata import BinaryMetadata

# Functions whose presence is worth flagging — NOT proof of a vulnerability,
# just a starting point for the context-bearing finding we generate.
_UNSAFE_FUNCTIONS = {
    "strcpy": "Unbounded string copy; can overflow the destination buffer if input length isn't validated.",
    "strcat": "Unbounded string concatenation; same overflow risk as strcpy.",
    "gets": "Reads unbounded input with no length check; effectively always unsafe.",
    "sprintf": "Unbounded formatted write; can overflow if the formatted result exceeds the destination buffer.",
    "system": "Executes a shell command; if any part of the command is attacker-influenced, this is a command-injection sink.",
    "popen": "Executes a shell command via a pipe; same injection concerns as system().",
    "exec": "Executes a program; injection risk if arguments are attacker-influenced.",
    "vsprintf": "Unbounded formatted write via varargs; same risk class as sprintf.",
}

_SECRET_KEYWORDS = ("password", "passwd", "secret", "api_key", "apikey", "token", "private_key", "aws_secret")
_SECRET_VALUE_PATTERN = re.compile(r"^(?=.*[A-Za-z])(?=.*[0-9!@#$%^&*]).{8,64}$")
_HEX_SECRET_PATTERN = re.compile(r"^[0-9a-fA-F]{32,64}$")
# Generic ELF/PE dynamic-linking metadata that happens to match the secret-SHAPE heuristic above (mixed
# letters/digits/punctuation) in any binary, on any platform -- a shared-library filename, a loader path, or
# a symbol-versioning tag is never a credential. Filtered here, not per-target, so it applies uniformly.
_DYNAMIC_LINKER_NOISE = (
    re.compile(r"^lib[a-z0-9_.+-]+\.so(\.[0-9]+)*$", re.IGNORECASE),   # libc.so.6, libpthread.so.0, ...
    re.compile(r"^/lib(64)?/[^\s]+\.so(\.[0-9]+)*$", re.IGNORECASE),  # /lib64/ld-linux-x86-64.so.2, ...
    re.compile(r"^[A-Z][A-Z0-9_]*_[0-9]+(\.[0-9]+)*$"),                # GLIBC_2.34, CXXABI_1.3, GLIBCXX_3.4.21, ...
)


def _is_dynamic_linker_noise(value: str) -> bool:
    return any(p.match(value) for p in _DYNAMIC_LINKER_NOISE)


@dataclass
class Weakness:
    category: str
    title: str
    description: str
    severity: str  # info|low|medium|high|critical
    confidence: str  # low|medium|high
    function_name: str | None = None
    function_address: str | None = None
    matched_value: str | None = None  # the string/import that triggered the detector
    context: dict = field(default_factory=dict)


def _check_unsafe_functions(ghidra: GhidraAnalysisResult) -> list[Weakness]:
    weaknesses = []
    imported_names = {imp.name.lower(): imp for imp in ghidra.imports}
    for unsafe_name, rationale in _UNSAFE_FUNCTIONS.items():
        imp = imported_names.get(unsafe_name)
        if not imp:
            continue
        # Look for a function that calls or wraps it, for extra context —
        # best-effort only; absence doesn't change the finding's confidence.
        caller = next((f for f in ghidra.functions if unsafe_name in f.signature.lower()), None)
        weaknesses.append(
            Weakness(
                category="unsafe_function_usage",
                title=f"Use of potentially unsafe function '{unsafe_name}'",
                description=rationale,
                severity="medium" if unsafe_name in ("system", "popen", "exec") else "low",
                confidence="medium",
                function_name=caller.name if caller else None,
                function_address=caller.address if caller else None,
                matched_value=unsafe_name,
                context={"import_namespace": imp.namespace},
            )
        )
    return weaknesses


def _check_hardcoded_secrets(ghidra: GhidraAnalysisResult) -> list[Weakness]:
    weaknesses = []
    strings_by_value = [s for s in ghidra.strings]
    for s in strings_by_value:
        value_lower = s.value.lower()
        keyword_hit = next((k for k in _SECRET_KEYWORDS if k in value_lower), None)
        if keyword_hit:
            weaknesses.append(
                Weakness(
                    category="hardcoded_credential",
                    title="Embedded string suggestive of a credential/secret label",
                    description=(
                        f"A string containing the keyword '{keyword_hit}' was found embedded in the binary. "
                        "This does not by itself prove a working credential is present; it is "
                        "flagged for manual review of the surrounding code."
                    ),
                    severity="medium",
                    confidence="low",
                    matched_value=s.value[:80],
                    context={"address": s.address},
                )
            )
            continue
        # High-entropy-looking literal near a plausible secret shape (not a
        # real entropy calculation — just length/charset heuristics — kept
        # deliberately conservative/low-confidence).
        if _is_dynamic_linker_noise(s.value):
            continue
        if _HEX_SECRET_PATTERN.match(s.value) or _SECRET_VALUE_PATTERN.match(s.value):
            if len(s.value) >= 8 and not s.value.isalpha() and " " not in s.value:
                weaknesses.append(
                    Weakness(
                        category="hardcoded_credential",
                        title="Embedded string resembling a hardcoded secret value",
                        description=(
                            "A string with a shape consistent with a credential or key (mixed "
                            "character classes, no spaces) was found embedded in the binary. "
                            "Requires manual confirmation — this heuristic has a meaningful "
                            "false-positive rate."
                        ),
                        severity="high",
                        confidence="low",
                        matched_value=s.value[:80],
                        context={"address": s.address},
                    )
                )
    return weaknesses


def _check_weak_hardening(metadata: BinaryMetadata) -> list[Weakness]:
    weaknesses = []
    checksec = metadata.checksec
    if checksec.nx is False:
        weaknesses.append(
            Weakness(
                category="weak_binary_hardening",
                title="NX (data execution prevention) is disabled",
                description="The binary was built without NX, allowing code execution from writable memory "
                "if another memory-corruption weakness provides a write primitive.",
                severity="medium",
                confidence="high",
            )
        )
    if checksec.stack_canary is False:
        weaknesses.append(
            Weakness(
                category="weak_binary_hardening",
                title="Stack canary not present",
                description="The binary was built without stack-smashing protection, making stack buffer "
                "overflows more directly exploitable.",
                severity="medium",
                confidence="high",
            )
        )
    if checksec.pie is False:
        weaknesses.append(
            Weakness(
                category="weak_binary_hardening",
                title="PIE (position-independent executable) is disabled",
                description="The binary has a fixed load address, simplifying exploitation of any memory "
                "corruption weakness by removing ASLR's base-address randomisation for the main image.",
                severity="low",
                confidence="high",
            )
        )
    if checksec.relro == "none":
        weaknesses.append(
            Weakness(
                category="weak_binary_hardening",
                title="RELRO not enabled",
                description="The GOT is fully writable at runtime, which can ease GOT-overwrite exploitation "
                "techniques if a write primitive exists elsewhere.",
                severity="low",
                confidence="high",
            )
        )
    return weaknesses


def _check_suspicious_input_handling(ghidra: GhidraAnalysisResult) -> list[Weakness]:
    """Heuristic: a function whose signature takes a raw char* buffer and
    whose name/body suggests it copies input, cross-referenced against the
    unsafe-function-usage check above for corroboration. Deliberately
    conservative — flags for review, not a conclusion."""
    weaknesses = []
    unsafe_names = set(_UNSAFE_FUNCTIONS)
    unsafe_import_names = {imp.name.lower() for imp in ghidra.imports} & unsafe_names
    if not unsafe_import_names:
        return weaknesses
    for func in ghidra.functions:
        sig_lower = func.signature.lower()
        if "char *" in sig_lower or "char*" in sig_lower:
            if any(name in sig_lower or name in func.name.lower() for name in ("copy", "parse", "read", "input")):
                weaknesses.append(
                    Weakness(
                        category="suspicious_input_handling",
                        title=f"Function '{func.name}' handles raw buffer input alongside unsafe-function imports",
                        description=(
                            f"'{func.name}' ({func.signature}) takes a raw char* parameter and the binary "
                            f"imports unsafe functions ({', '.join(sorted(unsafe_import_names))}). Manual review "
                            "recommended to confirm whether input reaching this function is length-validated."
                        ),
                        severity="low",
                        confidence="low",
                        function_name=func.name,
                        function_address=func.address,
                    )
                )
    return weaknesses


def analyse(metadata: BinaryMetadata, ghidra: GhidraAnalysisResult) -> list[Weakness]:
    weaknesses: list[Weakness] = []
    weaknesses.extend(_check_unsafe_functions(ghidra))
    weaknesses.extend(_check_hardcoded_secrets(ghidra))
    weaknesses.extend(_check_weak_hardening(metadata))
    weaknesses.extend(_check_suspicious_input_handling(ghidra))
    return weaknesses
