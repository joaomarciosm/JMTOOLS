#!/usr/bin/env python3
"""JM Tools — CLI.

Exemplos:
    python cli.py case-new --name "Caso 001" --examiner "Fulano"
    python cli.py evidence-add --case 20261012-... --path backup.ab --desc "Backup do celular do investigado"
    python cli.py analyze --case 20261012-...
    python cli.py analyze --case 20261012-... --password abc123=senha-do-backup
    python cli.py timeline --case 20261012-...
    python cli.py process --case 20261012-...
    python cli.py search --case 20261012-... "termo de busca"
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
    credentials: dict[str, str] = {}
    for entry in args.password or []:
        item_id, _, password = entry.partition("=")
        if not password:
            print(f"Aviso: --password '{entry}' ignorado (formato esperado: ITEM_ID=senha)")
            continue
        credentials[item_id] = password
    case.run_analysis(actor=args.examiner or case.examiner, credentials=credentials)
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


def cmd_process(args: argparse.Namespace) -> None:
    case = Case.load(args.case, CASES_DIR)
    stats = case.run_processing(actor=args.examiner or case.examiner)
    print(f"Processamento concluído: {stats['files']} arquivos, {stats['indexed_text']} com texto indexado, "
          f"{stats['duplicates']} duplicados, {stats['known_ignored']} conhecidos/ignorados, "
          f"{stats['pii_hits']} padroes sensiveis encontrados, {stats['image_clusters']} clusters de imagem, "
          f"{stats['ocr_processed']} imagens com OCR.")
    for category, count in sorted(stats["categories"].items(), key=lambda kv: -kv[1]):
        print(f"  {category}: {count}")
    print(f"Índice salvo em: {case.index_path}")


def cmd_pii_report(args: argparse.Namespace) -> None:
    case = Case.load(args.case, CASES_DIR)
    hits = case.pii_report()
    if not hits:
        print("Nenhum padrão sensível encontrado (rode 'process' antes).")
        return
    for h in hits:
        print(f"[{h['type']}] {h['value']}  —  {h['path']} (item {h['evidence_item_id']})")


def cmd_image_clusters(args: argparse.Namespace) -> None:
    case = Case.load(args.case, CASES_DIR)
    clusters = case.image_clusters()
    if not clusters:
        print("Nenhum cluster de imagens semelhantes encontrado (rode 'process' antes).")
        return
    for cluster_id, items in clusters.items():
        print(f"Cluster {cluster_id} ({len(items)} imagens):")
        for item in items:
            print(f"  {item['path']} (item {item['evidence_item_id']})")


def cmd_search(args: argparse.Namespace) -> None:
    case = Case.load(args.case, CASES_DIR)
    results = case.search(args.query, limit=args.limit)
    if not results:
        print("Nenhum resultado.")
        return
    for r in results:
        dup = " [DUPLICADO]" if r["is_duplicate"] else ""
        print(f"[{r['category']}] {r['path']}{dup}")
        if r["snippet"].strip():
            print(f"    {r['snippet']}")


def cmd_android_devices(_args: argparse.Namespace) -> None:
    import core.android_adb as adb
    if not adb.is_available():
        print("adb não encontrado no PATH — instale o Android SDK Platform Tools.")
        return
    for d in adb.list_devices():
        print(f"{d['serial']}  ({d['state']})")


def cmd_android_info(args: argparse.Namespace) -> None:
    import core.android_adb as adb
    info = adb.device_info(serial=args.serial)
    for k, v in info.items():
        print(f"{k}: {v}")


def cmd_android_backup(args: argparse.Namespace) -> None:
    import core.android_adb as adb
    print("Confirme no aparelho a tela de backup (e defina uma senha lá, se quiser) para continuar...")
    path = adb.full_backup(Path(args.output), serial=args.serial)
    print(f"Backup salvo em: {path}")


def cmd_android_pull_ext(args: argparse.Namespace) -> None:
    import core.android_adb as adb
    paths = adb.find_paths_by_extension(args.ext, serial=args.serial)
    print(f"{len(paths)} arquivo(s) encontrado(s). Copiando...")
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    for p in paths:
        adb.pull_path(p, out_dir, serial=args.serial)
    print(f"Copiado para: {out_dir}")


def cmd_android_trash(args: argparse.Namespace) -> None:
    import core.android_adb as adb
    paths = adb.find_trash_paths(serial=args.serial)
    if not paths:
        print("Nenhuma pasta de lixeira encontrada.")
        return
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    for p in paths:
        print(f"  {p}")
        adb.pull_path(p, out_dir, serial=args.serial)
    print(f"Copiado para: {out_dir}")


def cmd_android_dumpsys(args: argparse.Namespace) -> None:
    import core.android_adb as adb
    if args.service:
        print(adb.dumpsys(args.service, args.extra or "", serial=args.serial))
    else:
        for s in adb.dumpsys_services(serial=args.serial):
            print(s)


def cmd_android_downgrade_backup(args: argparse.Namespace) -> None:
    import core.android_adb as adb
    print(f"Reinstalando {args.apk} sobre {args.package} (mantendo dados) e tirando backup...")
    path = adb.downgrade_and_backup(args.package, Path(args.apk), Path(args.output), serial=args.serial)
    print(f"Backup salvo em: {path}")


def cmd_ios_devices(_args: argparse.Namespace) -> None:
    import core.ios_libimobiledevice as idev
    if not idev.is_available():
        print(f"Ferramentas faltando no PATH: {', '.join(idev.missing_tools())} — instale libimobiledevice.")
        return
    for udid in idev.list_devices():
        print(udid)


def cmd_ios_info(args: argparse.Namespace) -> None:
    import core.ios_libimobiledevice as idev
    info = idev.device_info(udid=args.udid)
    for k, v in info.items():
        print(f"{k}: {v}")


def cmd_ios_screenshot(args: argparse.Namespace) -> None:
    import core.ios_libimobiledevice as idev
    path = idev.take_screenshot(Path(args.output), udid=args.udid)
    print(f"Screenshot salvo em: {path}")


def cmd_ios_backup(args: argparse.Namespace) -> None:
    import core.ios_libimobiledevice as idev
    if args.password:
        print("Ligando criptografia do backup com a senha fornecida (necessário para incluir o chaveiro)...")
        idev.set_backup_password(args.password, udid=args.udid)
    path = idev.full_backup(Path(args.output), udid=args.udid)
    print(f"Backup salvo em: {path}")


def cmd_launch_iped(args: argparse.Namespace) -> None:
    from core.external_tools import run_iped
    case = Case.load(args.case, CASES_DIR)
    output_dir = case.case_dir / "iped_output"
    print(f"Rodando IPED sobre {case.extracted_dir} -> {output_dir} ...")
    run_iped(Path(args.iped_exe), case.extracted_dir, output_dir)
    print(f"Concluído. Resultado em: {output_dir}")


def cmd_graph(args: argparse.Namespace) -> None:
    case = Case.load(args.case, CASES_DIR)
    counts = case.contact_counts()
    if not counts:
        print("Nenhum contato encontrado na timeline (rode 'analyze' antes).")
        return
    for contact, count in counts.items():
        print(f"{count:5d}  {contact}")


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
    p.add_argument(
        "--password", action="append", metavar="ITEM_ID=senha",
        help="Senha já conhecida para decodificar um item criptografado (repetível). "
             "Nunca é salva em disco.",
    )
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("timeline", help="Exibir a timeline agregada do caso")
    p.add_argument("--case", required=True)
    p.add_argument("--type", default=None, help="Filtrar por tipo de evento (ex: sms, call, partition_found)")
    p.set_defaults(func=cmd_timeline)

    p = sub.add_parser("report", help="Gerar laudo em Markdown para o caso")
    p.add_argument("--case", required=True)
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("process", help="Indexar (texto completo + categorização + dedup) os arquivos extraídos")
    p.add_argument("--case", required=True)
    p.add_argument("--examiner", default=None)
    p.set_defaults(func=cmd_process)

    p = sub.add_parser("search", help="Buscar por texto no índice do caso (requer 'process' antes)")
    p.add_argument("--case", required=True)
    p.add_argument("query")
    p.add_argument("--limit", type=int, default=100)
    p.set_defaults(func=cmd_search)

    p = sub.add_parser("pii-report", help="Listar padrões sensíveis encontrados (requer 'process' antes)")
    p.add_argument("--case", required=True)
    p.set_defaults(func=cmd_pii_report)

    p = sub.add_parser("image-clusters", help="Listar grupos de imagens semelhantes (requer 'process' antes)")
    p.add_argument("--case", required=True)
    p.set_defaults(func=cmd_image_clusters)

    p = sub.add_parser("graph", help="Listar contatos por frequência de comunicação (requer 'analyze' antes)")
    p.add_argument("--case", required=True)
    p.set_defaults(func=cmd_graph)

    # ---- Aquisição Android via ADB (aparelho já conectado e com depuração USB autorizada) ----

    p = sub.add_parser("android-devices", help="Listar aparelhos Android conectados via ADB")
    p.set_defaults(func=cmd_android_devices)

    p = sub.add_parser("android-info", help="Informações do aparelho Android conectado")
    p.add_argument("--serial", default=None)
    p.set_defaults(func=cmd_android_info)

    p = sub.add_parser("android-backup", help="Backup completo via 'adb backup' (confirme no aparelho)")
    p.add_argument("--output", required=True, help="Caminho do arquivo .ab de saída")
    p.add_argument("--serial", default=None)
    p.set_defaults(func=cmd_android_backup)

    p = sub.add_parser("android-pull-ext", help="Copiar todos os arquivos de uma extensão do /sdcard")
    p.add_argument("--ext", required=True, help="Extensão sem ponto, ex: jpg")
    p.add_argument("--output", required=True)
    p.add_argument("--serial", default=None)
    p.set_defaults(func=cmd_android_pull_ext)

    p = sub.add_parser("android-trash", help="Copiar pastas de lixeira de apps (ex: WhatsApp/.Trash)")
    p.add_argument("--output", required=True)
    p.add_argument("--serial", default=None)
    p.set_defaults(func=cmd_android_trash)

    p = sub.add_parser("android-dumpsys", help="Listar serviços dumpsys ou rodar um específico")
    p.add_argument("--service", default=None, help="Nome do serviço (ex: battery); omita para listar todos")
    p.add_argument("--extra", default=None, help="Argumentos extras do dumpsys")
    p.add_argument("--serial", default=None)
    p.set_defaults(func=cmd_android_dumpsys)

    p = sub.add_parser(
        "android-downgrade-backup",
        help="Reinstalar versão mais antiga (fornecida por você) de um app e tirar backup dele",
    )
    p.add_argument("--package", required=True, help="Ex: com.whatsapp")
    p.add_argument("--apk", required=True, help="Caminho do APK mais antigo, legítimo, já obtido por você")
    p.add_argument("--output", required=True, help="Caminho do .ab de saída")
    p.add_argument("--serial", default=None)
    p.set_defaults(func=cmd_android_downgrade_backup)

    # ---- Aquisição iOS via libimobiledevice (aparelho já pareado/confiado) ----

    p = sub.add_parser("ios-devices", help="Listar aparelhos iOS conectados")
    p.set_defaults(func=cmd_ios_devices)

    p = sub.add_parser("ios-info", help="Informações do aparelho iOS conectado")
    p.add_argument("--udid", default=None)
    p.set_defaults(func=cmd_ios_info)

    p = sub.add_parser("ios-screenshot", help="Tirar screenshot da tela do aparelho iOS")
    p.add_argument("--output", required=True)
    p.add_argument("--udid", default=None)
    p.set_defaults(func=cmd_ios_screenshot)

    p = sub.add_parser("ios-backup", help="Backup completo via idevicebackup2")
    p.add_argument("--output", required=True, help="Pasta de saída do backup")
    p.add_argument(
        "--password", default=None,
        help="Se informado, liga a criptografia do backup com essa senha antes (inclui o chaveiro)",
    )
    p.add_argument("--udid", default=None)
    p.set_defaults(func=cmd_ios_backup)

    # ---- Integração com ferramentas externas ----

    p = sub.add_parser("launch-iped", help="Rodar o IPED de verdade (se instalado) sobre os arquivos extraídos do caso")
    p.add_argument("--case", required=True)
    p.add_argument("--iped-exe", required=True, help="Caminho do iped.exe instalado")
    p.set_defaults(func=cmd_launch_iped)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
