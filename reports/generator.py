"""Geração de laudo (relatório) em Markdown a partir de um caso."""
from __future__ import annotations

from pathlib import Path

from core.case import Case


def generate_markdown(case: Case) -> str:
    lines: list[str] = []
    lines.append(f"# Laudo Pericial — {case.name}")
    lines.append("")
    lines.append(f"- **Caso:** {case.case_id}")
    lines.append(f"- **Examinador:** {case.examiner}")
    lines.append(f"- **Criado em:** {case.created_at}")
    lines.append("")

    lines.append("## Itens de evidência")
    lines.append("")
    lines.append("| ID | Caminho original | Descrição | SHA-256 | Adicionado em |")
    lines.append("|---|---|---|---|---|")
    for item in case.evidence:
        lines.append(
            f"| {item.item_id} | `{item.source_path}` | {item.description} | `{item.sha256}` | {item.added_at} |"
        )
    lines.append("")

    lines.append("## Cadeia de custódia")
    lines.append("")
    lines.append("| Data/hora | Ator | Ação | Detalhe |")
    lines.append("|---|---|---|---|")
    for entry in case.custody.entries:
        lines.append(f"| {entry.timestamp} | {entry.actor} | {entry.action} | {entry.detail} |")
    lines.append("")

    lines.append("## Timeline de eventos")
    lines.append("")
    lines.append(f"Total de eventos: {len(case.timeline)}")
    lines.append("")
    lines.append("| Timestamp | Módulo | Tipo | Descrição |")
    lines.append("|---|---|---|---|")
    for event in case.timeline.sorted_events():
        desc = event.description.replace("|", "\\|")
        lines.append(f"| {event.timestamp} | {event.source_module} | {event.event_type} | {desc} |")

    return "\n".join(lines) + "\n"


def write_report(case: Case, output_path: Path | None = None) -> Path:
    output_path = output_path or (case.case_dir / "laudo.md")
    output_path.write_text(generate_markdown(case), encoding="utf-8")
    case.custody.record(case.examiner, "report_generated", f"path={output_path}")
    case.save()
    return output_path
