"""Smoke test: instancia a GUI, abre um caso real, forca o fluxo completo
(criar caso -> adicionar evidencias -> analisar -> gerar laudo) sem input do
usuario, e fecha. Serve so para pegar erros de construcao de widget/layout
que um py_compile nao pega."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import gui as gui_module  # noqa: E402
from gui import JMToolsApp, CASES_DIR  # noqa: E402
from core.case import Case  # noqa: E402

gui_module.messagebox.askyesno = lambda *a, **k: False  # evita dialogo modal bloqueante no teste automatizado

FIXTURES = Path(__file__).parent / "fixtures"


def main() -> None:
    app = JMToolsApp()
    app.update()

    case = Case.create(name="Smoke GUI", examiner="smoke-test", cases_dir=CASES_DIR)
    case.add_evidence(FIXTURES / "sample_backup.ab", description="android", actor="smoke-test")
    case.add_evidence(FIXTURES / "sample_disk.img", description="disk", actor="smoke-test")
    case.run_analysis(actor="smoke-test")

    app.open_case(case)
    app.update()

    case_frame = app.container.winfo_children()[0]
    case_frame._refresh_all()
    app.update()

    case_frame._generate_report()
    app.update()

    print("EVIDENCE ROWS:", len(case_frame.evidence_tab.evidence_tree.get_children()))
    print("TIMELINE ROWS:", len(case_frame.timeline_tab.timeline_tree.get_children()))
    print("CUSTODY ROWS:", len(case_frame.custody_tab.custody_tree.get_children()))

    app.destroy()
    print("SMOKE GUI OK")


if __name__ == "__main__":
    main()
