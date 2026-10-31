"""Static analysis of a binary this agent ACQUIRED itself (acquisition.py), as opposed to one an operator
supplied directly. Three things make this path different from the ordinary organiser-supplied one:

1. The documented synthetic Ghidra fixture (ghidra_adapter._synthetic_result) is never used here. That
   fixture exists so the rest of the pipeline can be exercised without a Ghidra install; substituting its
   canned strings for a REAL file's content would mean a "recovered credential" is actually fabricated demo
   data. The real tiers, in order, are: full PyGhidra analysis (disassembly, decompilation, call graph) ->
   a raw byte-level string scan of the real file (Ghidra unavailable) -> an explicit incomplete result
   (nothing usable could be produced). No fabricated findings, ever.
2. When full analysis is available, every function is checked against credential_recovery.py's generic
   structural heuristic; a function matching a known STATIC transform (currently: a per-byte XOR against a
   rotating key, read entirely from fixed bytes in the binary) has its value derived and the raw value is
   written to protected storage immediately -- it is NEVER placed in the Weakness/Finding/Evidence objects
   that flow into the ordinary report/event pipeline, only a `credential_ref`.
3. Every hardcoded-credential-shaped weakness is annotated with full provenance (SHA-256, source URL,
   extraction method, confidence, limitations) and an explicit, evidence-based statement of whether the
   binary's OWN other content corroborates it belonging to the service that led here.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from app.agents.binary_analysis.acquisition import AcquiredBinary
from app.agents.binary_analysis.credential_recovery import derive_value, find_validation_candidates
from app.agents.binary_analysis.ghidra_adapter import GhidraAnalysisResult, GhidraString
from app.agents.binary_analysis.metadata import BinaryMetadata, identify_binary
from app.agents.binary_analysis.pyghidra_adapter import analyse as pyghidra_analyse
from app.agents.binary_analysis.pyghidra_adapter import read_memory as pyghidra_read_memory
from app.agents.binary_analysis.raw_strings import extract_printable_strings
from app.agents.binary_analysis.static_analysis import Weakness, analyse
from app.core.exceptions import ToolExecutionError
from app.core.protected_storage import CredentialProvenance, store_secret

logger = logging.getLogger("ape.binary_agent.discovered_artifact")

ANALYSIS_FULL = "full"                 # real PyGhidra: disassembly, decompilation, call graph
ANALYSIS_STRINGS_ONLY = "strings_only"  # Ghidra unavailable: real byte-level string scan of the real file
ANALYSIS_NONE = "none"                 # nothing usable could be produced -- an explicit incomplete result

GHIDRA_TIMEOUT_SECONDS = 180.0


@dataclass
class DiscoveredBinaryAnalysis:
    acquired: AcquiredBinary
    metadata: BinaryMetadata | None = None
    analysis_depth: str = ANALYSIS_NONE
    weaknesses: list[Weakness] = field(default_factory=list)
    recovered_credentials: list[dict] = field(default_factory=list)  # [{credential_ref, function_name, ...}] -- NEVER the value
    errors: list[str] = field(default_factory=list)

    @property
    def incomplete(self) -> bool:
        return self.analysis_depth == ANALYSIS_NONE


def _try_full_analysis(acquired: AcquiredBinary, *, output_dir: Path) -> tuple[GhidraAnalysisResult | None, list[str]]:
    errors: list[str] = []
    try:
        pg = pyghidra_analyse(acquired.saved_path, timeout_seconds=GHIDRA_TIMEOUT_SECONDS, project_dir=output_dir)
    except ToolExecutionError as exc:
        errors.append(f"pyghidra: {exc}")
        return None, errors
    strings = [GhidraString(address=addr, value=val) for addr, val in pg.strings]
    functions = []
    from app.agents.binary_analysis.ghidra_adapter import GhidraFunction
    for f in pg.functions:
        functions.append(GhidraFunction(name=f.name, address=f.address, signature=f.signature,
                                        is_thunk=f.is_thunk, is_external=f.is_external, called_by=f.callers))
    from app.agents.binary_analysis.ghidra_adapter import GhidraImport
    imports = [GhidraImport(name=n) for n in pg.imports]
    ghidra = GhidraAnalysisResult(
        program_name=pg.program_name, language_id=pg.language_id, functions=functions, strings=strings,
        imports=imports, used_fixture=False,
        decompiled_by_function={f.name: f.decompiled_c for f in pg.functions if f.decompiled_c},
    )
    return ghidra, errors


def _recover_credentials(
    ghidra: GhidraAnalysisResult, acquired: AcquiredBinary, *, output_dir: Path,
    correlation_terms: tuple[str, ...],
) -> tuple[list[Weakness], list[dict], list[str]]:
    decompiled: dict[str, str] = ghidra.decompiled_by_function
    if not decompiled:
        return [], [], []
    errors: list[str] = []
    weaknesses: list[Weakness] = []
    recovered: list[dict] = []
    terms_lower = {t.lower() for t in correlation_terms if t}

    for candidate in find_validation_candidates(decompiled):
        if candidate.xor_schedule is None:
            continue
        schedule = candidate.xor_schedule
        try:
            mem = pyghidra_read_memory(acquired.saved_path, schedule.array_address, schedule.length,
                                       timeout_seconds=GHIDRA_TIMEOUT_SECONDS, project_dir=output_dir)
            value = derive_value(schedule, mem)
        except (ToolExecutionError, ValueError) as exc:
            errors.append(f"credential derivation for {candidate.function_name}: {exc}")
            continue

        text_lower = decompiled.get(candidate.function_name, "").lower()
        corroborating = sorted(t for t in terms_lower if t in text_lower)
        confidence = "medium" if corroborating else "low"
        limitations = (
            "Derived entirely from fixed bytes/constants present in this binary (array contents, key "
            "phrase, accumulator schedule) via a per-byte XOR transform recognised structurally in the "
            "decompiled code -- not a brute-force guess and not read from a literal string. Confidence is "
            "capped at 'medium': the pattern-match is generic and could, in principle, match an unrelated "
            "transform with the same shape."
        )
        provenance = CredentialProvenance(
            source_binary_sha256=acquired.sha256, source_url=acquired.source_url,
            function_name=candidate.function_name, function_address=None,
            extraction_method="ghidra_decompiled_xor_key_schedule_recovery", confidence=confidence,
            limitations=limitations, associated_service_id=None,
        )
        credential_ref = store_secret(value, provenance)
        recovered.append({
            "credential_ref": credential_ref, "function_name": candidate.function_name,
            "confidence": confidence, "corroborating_terms": corroborating,
        })
        weaknesses.append(Weakness(
            category="recovered_credential",
            title=f"A statically-derived credential was recovered from function '{candidate.function_name}'",
            description=(
                f"Function '{candidate.function_name}' validates its input with a per-byte XOR transform "
                f"against fixed data at {schedule.as_context()['array_address']} and a repeating "
                f"{len(schedule.key_phrase)}-byte key phrase; the "
                "expected value was derived from the binary's own bytes. The value itself is withheld (see "
                f"protected storage ref {credential_ref}), consistent with policy -- it is never placed in "
                "an ordinary report, event, or console output."
            ),
            severity="high", confidence=confidence,
            function_name=candidate.function_name,
            matched_value=None,
            context={"sha256": acquired.sha256, "source_url": acquired.source_url,
                     "extraction_method": "ghidra_decompiled_xor_key_schedule_recovery",
                     "credential_ref": credential_ref, "confidence": confidence, "limitations": limitations,
                     "service_correlation": (f"corroborated: this function's own code references {corroborating}"
                                             if corroborating else
                                             "unconfirmed: nothing in this function's own code references the "
                                             "service that led here -- treat the association as unverified"),
                     "schedule": schedule.as_context()},
        ))
    return weaknesses, recovered, errors


def analyse_discovered_binary(
    acquired: AcquiredBinary, *, output_dir: Path, correlation_terms: tuple[str, ...] = (),
) -> DiscoveredBinaryAnalysis:
    """`correlation_terms`: values already published about the service that led to this binary (its port
    number as a string, its service/application name) -- used ONLY to annotate whether an extracted
    candidate corroborates association with that service. Never itself treated as a credential, never
    substitutes for the binary's own content, and absence of a match is reported honestly, not suppressed."""
    result = DiscoveredBinaryAnalysis(acquired=acquired)

    try:
        result.metadata = identify_binary(acquired.saved_path)
    except ToolExecutionError as exc:
        result.errors.append(f"identify_binary: {exc}")
        return result

    ghidra, full_errors = _try_full_analysis(acquired, output_dir=output_dir)
    result.errors.extend(full_errors)
    if ghidra is not None:
        result.analysis_depth = ANALYSIS_FULL
        cred_weaknesses, recovered, cred_errors = _recover_credentials(
            ghidra, acquired, output_dir=output_dir, correlation_terms=correlation_terms,
        )
        result.recovered_credentials = recovered
        result.errors.extend(cred_errors)
    else:
        try:
            strings = extract_printable_strings(acquired.saved_path)
        except OSError as exc:
            result.errors.append(f"raw string extraction failed: {exc}")
            return result
        if not strings:
            result.errors.append("no printable strings found in the acquired file: incomplete result")
            return result
        ghidra = GhidraAnalysisResult(program_name=acquired.saved_path.name, strings=strings, used_fixture=False)
        result.analysis_depth = ANALYSIS_STRINGS_ONLY
        cred_weaknesses = []

    weaknesses = analyse(result.metadata, ghidra)
    terms_lower = {t.lower() for t in correlation_terms if t}
    all_values_lower = [s.value.lower() for s in ghidra.strings]
    corroborating = sorted(t for t in terms_lower if any(t in v for v in all_values_lower))

    for w in weaknesses:
        w.context = {**w.context, "sha256": acquired.sha256, "source_url": acquired.source_url,
                     "extraction_method": "ghidra_headless" if result.analysis_depth == ANALYSIS_FULL
                     else "raw_printable_string_scan"}
        if w.category != "hardcoded_credential":
            continue
        if corroborating:
            w.context["service_correlation"] = f"corroborated: this binary's own content also references {corroborating}"
            w.description += f" Corroborated by the binary's own reference to {corroborating}."
        else:
            w.context["service_correlation"] = (
                "unconfirmed: nothing else in this binary references the service that led here -- this "
                "candidate may be an unrelated string and must not be treated as confirmed"
            )
            w.description += (
                " Not yet corroborated as belonging to the specific service that led to this binary; treat "
                "as a candidate only."
            )
            w.confidence = "low"

    result.weaknesses = cred_weaknesses + weaknesses
    return result
