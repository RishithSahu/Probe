"""Challenge artifacts: record WHERE something that looks like a designated challenge artifact (a flag, a CTF marker) was
seen, and nothing more.

What the probe is allowed to do about a flag is a question for the official challenge rules and the network owner's approval,
not for the probe. The probe therefore does discovery only: it notes that service output it had already collected for
inventory purposes contains a flag-shaped marker, on which host/port, and withholds the value. It never fetches a page,
logs in, reads a file or probes further to obtain one; retrieval and deeper examination need explicit authorisation.
"""
from __future__ import annotations

import json
import re

_FLAG = re.compile(r"\b([A-Za-z][A-Za-z0-9_]{1,15})\{([A-Za-z0-9_\-!@#$%^&*+=./]{6,80})\}")
# code, not flags: markup/CSS/JS tokens that are followed by a brace in ordinary web content
_CODE_PREFIX = {"body", "html", "head", "div", "span", "a", "p", "ul", "li", "ol", "table", "td", "tr", "th", "form", "input",
                "button", "script", "style", "function", "if", "for", "while", "else", "return", "class", "id", "var", "let",
                "const", "switch", "try", "catch", "do", "img", "svg", "path", "label", "select", "textarea", "main", "nav",
                "header", "footer", "section", "article", "pre", "code", "h1", "h2", "h3", "h4", "h5", "h6", "root", "font"}
_WORDS = ("capture the flag", "ctf", "flag.txt", "the flag is", "secret flag")

RULES = {
    "official_rules_provided_to_the_probe": False,
    "applied_reading": "most restrictive: discovery of devices, services and topology inside the authorised scope only",
    "authorised": ["discovering and inventorying devices, services and network structure inside the authorised scope"],
    "requires_explicit_approval": ["retrieving or reading any flag/artifact", "logging in to or examining any machine",
                                   "probing any network discovered outside the authorised scope",
                                   "tunnelling or pivoting of any kind"],
}


def find_candidates(hosts: list[dict]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.get("open_ports") or []:
            scripts = p.get("scripts") or {}
            if isinstance(scripts, str):                    # the store keeps script output as JSON text
                try:
                    scripts = json.loads(scripts)
                except ValueError:
                    scripts = {}
            texts = {"banner": p.get("banner") or "", **{f"script:{k}": str(v) for k, v in scripts.items()}}
            for field, text in texts.items():
                if not text:
                    continue
                m = next((x for x in _FLAG.finditer(text) if x.group(1).lower() not in _CODE_PREFIX), None)
                if m:
                    prefix = m.group(1)
                    out.append({"address": h["ip"], "port": p["port"], "proto": p.get("proto", "tcp"), "field": field,
                                "shape": f"{prefix}{{...}} ({len(m.group(0))} chars)", "value": "withheld",
                                "status": "flag-shaped marker recorded; no retrieval or examination performed",
                                "needs": "explicit challenge authorisation before any examination"})
                    break
                low = text.lower()
                hit = next((w for w in _WORDS if w in low), None)
                if hit:
                    out.append({"address": h["ip"], "port": p["port"], "proto": p.get("proto", "tcp"), "field": field,
                                "shape": f"mentions '{hit}'", "value": "withheld",
                                "status": "challenge-related wording recorded; no retrieval or examination performed",
                                "needs": "explicit challenge authorisation before any examination"})
                    break
    return out
