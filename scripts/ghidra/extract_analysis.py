# Ghidra Headless post-analysis script.
#
# Run via `analyzeHeadless <project_dir> <project_name> -import <binary>
#   -postScript extract_analysis.py <output_json_path> -deleteProject`
#
# Jython 2.7 (Ghidra's scripting runtime) — NOT Python 3. Keep this file
# syntactically Jython-2.7-compatible (no f-strings, no walrus, etc).
#
# Performs read-only extraction: functions, strings, imported symbols and
# their cross-references. Never modifies, patches, or executes the analysed
# binary. Output is a single JSON document consumed by
# app/agents/binary_analysis/ghidra_adapter.py.
import json

from ghidra.program.model.symbol import SymbolType  # noqa: E402
from ghidra.util.task import ConsoleTaskMonitor  # noqa: E402


def _get_output_path():
    args = getScriptArgs()  # noqa: F821 - provided by Ghidra script environment
    if not args:
        raise RuntimeError("extract_analysis.py requires the output JSON path as its argument")
    return args[0]


def extract_functions(program, monitor):
    functions = []
    func_manager = program.getFunctionManager()
    for func in func_manager.getFunctions(True):
        if monitor.isCancelled():
            break
        entry = func.getEntryPoint()
        refs = []
        ref_iter = program.getReferenceManager().getReferencesTo(entry)
        for ref in ref_iter:
            refs.append(str(ref.getFromAddress()))
        functions.append({
            "name": func.getName(),
            "address": str(entry),
            "signature": str(func.getSignature()),
            "is_thunk": func.isThunk(),
            "is_external": func.isExternal(),
            "called_by": refs[:20],  # cap to keep output bounded
        })
    return functions


def extract_strings(program, monitor):
    strings = []
    listing = program.getListing()
    data_iter = listing.getDefinedData(True)
    for data in data_iter:
        if monitor.isCancelled():
            break
        if data.hasStringValue():
            value = data.getDefaultValueRepresentation()
            strings.append({"address": str(data.getAddress()), "value": value})
    return strings


def extract_imports(program):
    imports = []
    symtab = program.getSymbolTable()
    ext_iter = symtab.getExternalSymbols()
    for sym in ext_iter:
        imports.append({"name": sym.getName(), "namespace": str(sym.getParentNamespace())})
    return imports


def run():
    monitor = ConsoleTaskMonitor()
    program = getCurrentProgram()  # noqa: F821 - provided by Ghidra script environment
    output_path = _get_output_path()

    result = {
        "program_name": program.getName(),
        "language_id": str(program.getLanguageID()),
        "image_base": str(program.getImageBase()),
        "functions": extract_functions(program, monitor),
        "strings": extract_strings(program, monitor),
        "imports": extract_imports(program),
    }

    with open(output_path, "w") as fh:
        json.dump(result, fh, indent=2)


run()
