"""Readable report sections built only from the consolidated report data."""
from __future__ import annotations

from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.platypus import KeepTogether, LongTable, PageBreak, Paragraph, Spacer, TableStyle


def text(value) -> str:
    return escape(str(value if value is not None else "unknown"))


def table(headers, rows, styles, width):
    cells = [[Paragraph(text(value), styles["BodyText"]) for value in row] for row in [headers, *rows]]
    return LongTable(cells, colWidths=[width / len(headers)] * len(headers), repeatRows=1, hAlign="LEFT", style=TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))


def coverage_section(data, styles):
    coverage = data.get("assessment_coverage", {})
    parts = [Paragraph("Coverage and Completion", styles["Heading1"])]
    parts.append(Paragraph(
        f"Execution: {text(coverage.get('execution_status', 'unknown'))}. "
        f"Discovery: {text(coverage.get('discovery_status', 'unknown'))}. "
        f"Overall coverage: <b>{text(coverage.get('overall', 'unknown'))}</b>.", styles["Normal"],
    ))
    for surface, record in coverage.get("surfaces", {}).items():
        parts.append(Paragraph(
            f"{text(surface)}: {text(record['status'])}; required: {'yes' if record['required'] else 'no'}.",
            styles["Normal"],
        ))
    parts.append(Paragraph(
        "Execution completion does not establish complete discovery. Unknown coverage requires further evidence.",
        styles["Normal"],
    ))
    return parts


def inventory_section(data, styles, width):
    parts = [PageBreak(), Paragraph("Device and Service Inventory", styles["Heading1"])]
    graph = data.get("network_graph_overview") or {}
    parts.append(Paragraph(f"Inventory source: {text(graph.get('raw_source_ref') or graph.get('generated_by', 'unavailable'))}", styles["Normal"]))
    if not graph.get("assets"):
        parts.append(Paragraph("No device inventory was supplied.", styles["Normal"]))
    for asset in graph.get("assets", []):
        parts.append(Paragraph(text(asset["asset_id"]), styles["Heading3"]))
        parts.append(Paragraph(
            f"Address: {text(asset.get('ip'))}. Hostname: {text(asset.get('hostname'))}. "
            f"Classification: {text(asset.get('verdict'))}. Held: {'yes' if asset.get('held') else 'no'}.",
            styles["Normal"],
        ))
        services = asset.get("services", [])
        if services:
            parts.append(table(
                ["Service ID", "Port / transport", "Service", "Product / version"],
                [[s["service_id"], f"{s['port']} / {s.get('protocol', 'tcp')}",
                  s.get("service_name") or "unidentified",
                  " / ".join(str(s[k]) for k in ("product", "version") if s.get(k)) or "unknown"] for s in services],
                styles, width,
            ))
        else:
            parts.append(Paragraph("No services recorded.", styles["Normal"]))
        parts.append(Spacer(1, 8))
    return parts


def attack_paths_section(data, styles):
    parts = [PageBreak(), Paragraph("Attack Paths and Observed Relationships", styles["Heading1"])]
    parts.append(Paragraph(
        "Connectivity and potential relationships do not prove access. A confirmed weakness describes a weakness; "
        "it does not establish an access transition. Only separately validated transition evidence can support that claim.",
        styles["Normal"],
    ))
    edges = data.get("attack_paths", [])
    if not edges:
        parts.append(Paragraph("No attack-path relationships were recorded.", styles["Normal"]))
    for index, edge in enumerate(edges, 1):
        relation = edge.get("relation", "unknown")
        if relation == "AFFECTED_BY" and edge.get("evidence_backed"):
            label = "Confirmed weakness relationship"
        elif relation == "VERIFIED_TRANSITION":
            label = "Transition claim - inspect its separate verification evidence"
        else:
            label = "Structural / potential relationship"
        group = [Paragraph(f"{index}. {text(label)}", styles["Heading3"]),
                 Paragraph(f"Source: {text(edge.get('source'))}<br/>Target: {text(edge.get('target'))}", styles["Normal"])]
        group.append(Paragraph(
            f"Relation: {text(relation)}. Finding: {text(edge.get('finding_id') or 'none')}. "
            f"Evidence-backed indicator: {text(bool(edge.get('evidence_backed')))}.", styles["Normal"],
        ))
        parts.append(KeepTogether(group))
    return parts


def evidence_section(data, styles):
    parts = [PageBreak(), Paragraph("Evidence Index", styles["Heading1"])]
    parts.append(Paragraph(
        "This index links observations to findings. The JSON report retains structured excerpts and artifact references. "
        "An evidence reference alone does not establish that its contents prove the claim.", styles["Normal"],
    ))
    evidence = data.get("evidence", [])
    if not evidence:
        parts.append(Paragraph("No evidence records were supplied.", styles["Normal"]))
    for item in evidence:
        parts.append(Paragraph(text(item["evidence_id"]), styles["Heading3"]))
        parts.append(Paragraph(
            f"Finding: {text(item.get('finding_id'))}. Type: {text(item.get('evidence_type'))}. "
            f"Tool: {text(item.get('source_tool'))}.", styles["Normal"],
        ))
        parts.append(Paragraph(text(item.get("description", "")), styles["Normal"]))
    return parts
