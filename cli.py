#!/usr/bin/env python3
"""JM Tools — CLI.

Exemplos:
    python cli.py case-new --name "Caso 001" --examiner "Fulano"
    python cli.py evidence-add --case 20261012-... --path backup.ab --desc "Backup do celular do investigado"
    python cli.py analyze --case 20261012-...
    python cli.py timeline --case 20261012-...
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from core.case import Case
from reports.generator import write_report

CASES_DIR = Path(__file__).parent / "cases"


def cmd_case_new(args: argparse.Namespace) -> None:
    case = Case.create(name=args.name, examiner=args.examiner, cases_dir=CASES_DIR)
    print(f"Caso criado: {case.case_id}")
    print(f"Diretório: {case.case_dir}")


def cmd_evidence_add(args: argparse.Namespace) -> None:
    case = Case.load(args.case, CASES_DIR)
    item = case.add_evidence(Path(args.path), description=args.desc, actor=args.examiner or case.examiner)
    print(f"Evidência adicionada: item_id={item.item_id} sha256={item.sha256}")


def cmd_analyze(args: argparse.Namespace) -> None:
    case = Case.load(args.case, CASES_DIR)
    case.run_analysis(actor=args.examiner or case.examiner)
    print(f"Análise concluída. {len(case.timeline)} eventos na timeline.")
    print(f"Timeline salva em: {case.timeline_path}")


def cmd_timeline(args: argparse.Namespace) -> None:
    case = Case.load(args.case, CASES_DIR)
    data = json.loads(case.timeline_path.read_text(encoding="utf-8")) if case.timeline_path.exists() else []
    if args.type:
        data = [e for e in data if e["event_type"] == args.type]
    for event in data:
        print(f"[{event['timestamp']}] ({event['event_type']}) {event['description']}")


def cmd_report(args: argparse.Namespace) -> None:
    case = Case.load(args.case, CASES_DIR)
    path = write_report(case)
    print(f"Laudo gerado em: {path}")


def cmd_case_list(_args: argparse.Namespace) -> None:
    if not CASES_DIR.exists():
        print("Nenhum caso encontrado.")
        return
    for case_dir in sorted(CASES_DIR.iterdir()):
        manifest = case_dir / "case.json"
        if manifest.exists():
            data = json.loads(manifest.read_text(encoding="utf-8"))
            print(f"{data['case_id']}  {data['name']}  (examinador: {data['examiner']})")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="jmtools", description="JM Tools — suíte forense digital")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("case-new", help="Criar um novo caso")
    p.add_argument("--name", required=True)
    p.add_argument("--examiner", required=True)
    p.set_defaults(func=cmd_case_new)

    p = sub.add_parser("case-list", help="Listar casos existentes")
    p.set_defaults(func=cmd_case_list)

    p = sub.add_parser("evidence-add", help="Adicionar item de evidência a um caso")
    p.add_argument("--case", required=True)
    p.add_argument("--path", required=True)
    p.add_argument("--desc", default="")
    p.add_argument("--examiner", default=None)
    p.set_defaults(func=cmd_evidence_add)

    p = sub.add_parser("analyze", help="Rodar todos os módulos compatíveis sobre as evidências do caso")
    p.add_argument("--case", required=True)
    p.add_argument("--examiner", default=None)
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("timeline", help="Exibir a timeline agregada do caso")
    p.add_argument("--case", required=True)
    p.add_argument("--type", default=None, help="Filtrar por tipo de evento (ex: sms, call, partition_found)")
    p.set_defaults(func=cmd_timeline)

    p = sub.add_parser("report", help="Gerar laudo em Markdown para o caso")
    p.add_argument("--case", required=True)
    p.set_defaults(func=cmd_report)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
