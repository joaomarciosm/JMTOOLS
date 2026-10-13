#!/usr/bin/env python3
"""JM Tools — Interface Gráfica (Tkinter, biblioteca padrão do Python).

Reaproveita inteiramente core/case.py, core/plugin.py e reports/generator.py
— a GUI é só uma casca visual sobre a mesma lógica usada pelo CLI.
"""
from __future__ import annotations

import os
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

from core.case import Case
from reports.generator import write_report

CASES_DIR = Path(__file__).parent / "cases"


class JMToolsApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("JM Tools — Suíte Forense Digital")
        self.geometry("1000x650")
        self.minsize(800, 500)

        self.current_case: Case | None = None
        self.container = ttk.Frame(self)
        self.container.pack(fill="both", expand=True)

        self._build_style()
        self.show_start_frame()

    def _build_style(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("vista")
        except tk.TclError:
            pass
        style.configure("Header.TLabel", font=("Segoe UI", 14, "bold"))
        style.configure("SubHeader.TLabel", font=("Segoe UI", 10))

    def _clear_container(self) -> None:
        for widget in self.container.winfo_children():
            widget.destroy()

    def show_start_frame(self) -> None:
        self._clear_container()
        StartFrame(self.container, self).pack(fill="both", expand=True)

    def open_case(self, case: Case) -> None:
        self.current_case = case
        self._clear_container()
        CaseFrame(self.container, self, case).pack(fill="both", expand=True)


class StartFrame(ttk.Frame):
    def __init__(self, parent: tk.Widget, app: JMToolsApp) -> None:
        super().__init__(parent, padding=20)
        self.app = app

        ttk.Label(self, text="JM Tools", style="Header.TLabel").pack(anchor="w")
        ttk.Label(
            self,
            text="Suíte forense digital — aquisição e análise legítima (sem bypass/exploit)",
            style="SubHeader.TLabel",
        ).pack(anchor="w", pady=(0, 20))

        new_case_box = ttk.LabelFrame(self, text="Novo caso", padding=12)
        new_case_box.pack(fill="x", pady=(0, 16))

        ttk.Label(new_case_box, text="Nome do caso:").grid(row=0, column=0, sticky="w", padx=4, pady=4)
        self.name_entry = ttk.Entry(new_case_box, width=40)
        self.name_entry.grid(row=0, column=1, sticky="w", padx=4, pady=4)

        ttk.Label(new_case_box, text="Examinador:").grid(row=1, column=0, sticky="w", padx=4, pady=4)
        self.examiner_entry = ttk.Entry(new_case_box, width=40)
        self.examiner_entry.grid(row=1, column=1, sticky="w", padx=4, pady=4)

        ttk.Button(new_case_box, text="Criar caso", command=self._create_case).grid(
            row=2, column=0, columnspan=2, pady=(8, 0)
        )

        existing_box = ttk.LabelFrame(self, text="Casos existentes", padding=12)
        existing_box.pack(fill="both", expand=True)

        self.case_list = ttk.Treeview(
            existing_box, columns=("name", "examiner", "created_at"), show="headings", height=10
        )
        self.case_list.heading("name", text="Nome")
        self.case_list.heading("examiner", text="Examinador")
        self.case_list.heading("created_at", text="Criado em")
        self.case_list.pack(fill="both", expand=True, side="left")
        self.case_list.bind("<Double-1>", self._open_selected)

        scrollbar = ttk.Scrollbar(existing_box, orient="vertical", command=self.case_list.yview)
        self.case_list.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")

        ttk.Button(self, text="Abrir caso selecionado", command=self._open_selected).pack(pady=(10, 0), anchor="w")

        self._load_cases()

    def _load_cases(self) -> None:
        self._case_ids: dict[str, str] = {}
        if not CASES_DIR.exists():
            return
        for case_dir in sorted(CASES_DIR.iterdir()):
            manifest = case_dir / "case.json"
            if not manifest.exists():
                continue
            import json

            data = json.loads(manifest.read_text(encoding="utf-8"))
            row_id = self.case_list.insert(
                "", "end", values=(data["name"], data["examiner"], data["created_at"])
            )
            self._case_ids[row_id] = data["case_id"]

    def _create_case(self) -> None:
        name = self.name_entry.get().strip()
        examiner = self.examiner_entry.get().strip()
        if not name or not examiner:
            messagebox.showwarning("Campos obrigatórios", "Informe nome do caso e examinador.")
            return
        case = Case.create(name=name, examiner=examiner, cases_dir=CASES_DIR)
        self.app.open_case(case)

    def _open_selected(self, _event=None) -> None:
        selection = self.case_list.selection()
        if not selection:
            messagebox.showinfo("Nenhum caso selecionado", "Selecione um caso na lista.")
            return
        case_id = self._case_ids[selection[0]]
        case = Case.load(case_id, CASES_DIR)
        self.app.open_case(case)


class CaseFrame(ttk.Frame):
    def __init__(self, parent: tk.Widget, app: JMToolsApp, case: Case) -> None:
        super().__init__(parent, padding=12)
        self.app = app
        self.case = case
        self.credentials: dict[str, str] = {}  # item_id -> senha; só em memória, nunca salvo em disco

        header = ttk.Frame(self)
        header.pack(fill="x", pady=(0, 8))
        ttk.Label(header, text=f"Caso: {case.name}", style="Header.TLabel").pack(side="left")
        ttk.Label(header, text=f"  (ID {case.case_id} — Examinador: {case.examiner})",
                  style="SubHeader.TLabel").pack(side="left")
        ttk.Button(header, text="← Voltar", command=self.app.show_start_frame).pack(side="right")

        toolbar = ttk.Frame(self)
        toolbar.pack(fill="x", pady=(0, 8))
        ttk.Button(toolbar, text="+ Evidência (arquivo)", command=self._add_evidence_file).pack(side="left", padx=2)
        ttk.Button(toolbar, text="+ Evidência (pasta)", command=self._add_evidence_folder).pack(side="left", padx=2)
        ttk.Button(toolbar, text="🔑 Definir senha", command=self._set_credential).pack(side="left", padx=2)
        ttk.Button(toolbar, text="▶ Analisar", command=self._run_analysis).pack(side="left", padx=2)
        ttk.Button(toolbar, text="🗂 Processar/Indexar", command=self._run_processing).pack(side="left", padx=2)
        ttk.Button(toolbar, text="✔ Verificar integridade", command=self._verify_integrity).pack(side="left", padx=2)
        ttk.Button(toolbar, text="📄 Gerar laudo", command=self._generate_report).pack(side="left", padx=2)

        self.status_var = tk.StringVar(value="Pronto.")
        ttk.Label(self, textvariable=self.status_var, style="SubHeader.TLabel").pack(anchor="w", pady=(0, 4))

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True)

        self.evidence_tab = self._build_evidence_tab(notebook)
        self.timeline_tab = self._build_timeline_tab(notebook)
        self.search_tab = self._build_search_tab(notebook)
        self.custody_tab = self._build_custody_tab(notebook)
        notebook.add(self.evidence_tab, text="Evidências")
        notebook.add(self.timeline_tab, text="Timeline")
        notebook.add(self.search_tab, text="Busca")
        notebook.add(self.custody_tab, text="Cadeia de custódia")

        self._refresh_all()

    # ---------- construção das abas ----------

    def _build_evidence_tab(self, parent) -> ttk.Frame:
        frame = ttk.Frame(parent, padding=8)
        columns = ("item_id", "path", "desc", "sha256", "added_at")
        tree = ttk.Treeview(frame, columns=columns, show="headings")
        for col, label, width in [
            ("item_id", "ID", 90), ("path", "Caminho", 320), ("desc", "Descrição", 200),
            ("sha256", "SHA-256", 200), ("added_at", "Adicionado em", 160),
        ]:
            tree.heading(col, text=label)
            tree.column(col, width=width, anchor="w")
        tree.pack(fill="both", expand=True)
        frame.evidence_tree = tree  # type: ignore[attr-defined]
        return frame

    def _build_timeline_tab(self, parent) -> ttk.Frame:
        frame = ttk.Frame(parent, padding=8)

        filter_bar = ttk.Frame(frame)
        filter_bar.pack(fill="x", pady=(0, 6))
        ttk.Label(filter_bar, text="Filtrar por tipo de evento:").pack(side="left")
        self.event_type_filter = ttk.Combobox(filter_bar, values=["(todos)"], state="readonly", width=30)
        self.event_type_filter.set("(todos)")
        self.event_type_filter.pack(side="left", padx=6)
        self.event_type_filter.bind("<<ComboboxSelected>>", lambda _e: self._refresh_timeline())

        columns = ("timestamp", "module", "type", "description")
        tree = ttk.Treeview(frame, columns=columns, show="headings")
        for col, label, width in [
            ("timestamp", "Timestamp", 200), ("module", "Módulo", 160),
            ("type", "Tipo", 140), ("description", "Descrição", 420),
        ]:
            tree.heading(col, text=label)
            tree.column(col, width=width, anchor="w")
        tree.pack(fill="both", expand=True)

        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)

        frame.timeline_tree = tree  # type: ignore[attr-defined]
        return frame

    def _build_custody_tab(self, parent) -> ttk.Frame:
        frame = ttk.Frame(parent, padding=8)
        columns = ("timestamp", "actor", "action", "detail")
        tree = ttk.Treeview(frame, columns=columns, show="headings")
        for col, label, width in [
            ("timestamp", "Data/hora", 200), ("actor", "Ator", 120),
            ("action", "Ação", 180), ("detail", "Detalhe", 420),
        ]:
            tree.heading(col, text=label)
            tree.column(col, width=width, anchor="w")
        tree.pack(fill="both", expand=True)
        frame.custody_tree = tree  # type: ignore[attr-defined]
        return frame

    def _build_search_tab(self, parent) -> ttk.Frame:
        frame = ttk.Frame(parent, padding=8)

        bar = ttk.Frame(frame)
        bar.pack(fill="x", pady=(0, 6))
        ttk.Label(bar, text="Buscar:").pack(side="left")
        query_var = tk.StringVar()
        entry = ttk.Entry(bar, textvariable=query_var, width=50)
        entry.pack(side="left", padx=6)
        entry.bind("<Return>", lambda _e: self._run_search(query_var.get()))
        ttk.Button(bar, text="Buscar", command=lambda: self._run_search(query_var.get())).pack(side="left")
        ttk.Label(
            bar, text="(rode \"Processar/Indexar\" primeiro)", style="SubHeader.TLabel"
        ).pack(side="left", padx=10)

        columns = ("category", "path", "snippet")
        tree = ttk.Treeview(frame, columns=columns, show="headings")
        for col, label, width in [
            ("category", "Categoria", 120), ("path", "Caminho", 320), ("snippet", "Trecho encontrado", 420),
        ]:
            tree.heading(col, text=label)
            tree.column(col, width=width, anchor="w")
        tree.pack(fill="both", expand=True)
        frame.search_tree = tree  # type: ignore[attr-defined]
        frame.query_var = query_var  # type: ignore[attr-defined]
        return frame

    # ---------- ações ----------

    def _add_evidence_file(self) -> None:
        path = filedialog.askopenfilename(title="Selecionar arquivo de evidência")
        if path:
            self._add_evidence(Path(path))

    def _add_evidence_folder(self) -> None:
        path = filedialog.askdirectory(title="Selecionar pasta de evidência (backup iOS, storage DVR, dump IoT...)")
        if path:
            self._add_evidence(Path(path))

    def _add_evidence(self, path: Path) -> None:
        desc = simpledialog.askstring("Descrição", f"Descrição para '{path.name}':") or ""
        self.status_var.set(f"Calculando hash de {path.name}...")
        self.update_idletasks()
        try:
            item = self.case.add_evidence(path, description=desc, actor=self.case.examiner)
        except OSError as exc:
            messagebox.showerror("Erro ao adicionar evidência", str(exc))
            return

        password = simpledialog.askstring(
            "Senha / chave (opcional)",
            "Se este item precisar de uma credencial já conhecida para decodificar, informe "
            "agora:\n"
            "- Backup Android (.ab) criptografado: a senha\n"
            "- WhatsApp (.crypt12/.crypt14/.crypt15): o caminho do arquivo de chave "
            "(ou a chave hex de 64 dígitos, só para .crypt15)\n\n"
            "Deixe em branco se este item não precisar. Fica só em memória nesta sessão — "
            "nunca é salva no caso.",
            show="*",
        )
        if password:
            self.credentials[item.item_id] = password

        self.status_var.set("Evidência adicionada.")
        self._refresh_all()

    def _set_credential(self) -> None:
        if not self.case.evidence:
            messagebox.showinfo("Sem evidências", "Adicione uma evidência primeiro.")
            return
        item_id = simpledialog.askstring(
            "Definir senha", "ID do item de evidência (veja a aba Evidências):"
        )
        if not item_id or item_id not in {e.item_id for e in self.case.evidence}:
            if item_id:
                messagebox.showwarning("ID inválido", f"Nenhum item com ID '{item_id}' neste caso.")
            return
        password = simpledialog.askstring("Senha", f"Senha para o item {item_id}:", show="*")
        if password:
            self.credentials[item_id] = password
            self.status_var.set(f"Senha definida para o item {item_id}. Rode Analisar para aplicar.")

    def _run_analysis(self) -> None:
        self.status_var.set("Analisando evidências, por favor aguarde...")
        self.update_idletasks()

        def worker() -> None:
            self.case.run_analysis(actor=self.case.examiner, credentials=self.credentials)
            self.after(0, self._on_analysis_done)

        threading.Thread(target=worker, daemon=True).start()

    def _on_analysis_done(self) -> None:
        self.status_var.set(f"Análise concluída — {len(self.case.timeline)} eventos na timeline.")
        self._refresh_all()

    def _run_processing(self) -> None:
        self.status_var.set("Processando/indexando arquivos extraídos, aguarde...")
        self.update_idletasks()

        def worker() -> None:
            stats = self.case.run_processing(actor=self.case.examiner)
            self.after(0, lambda: self._on_processing_done(stats))

        threading.Thread(target=worker, daemon=True).start()

    def _on_processing_done(self, stats: dict) -> None:
        self.status_var.set(
            f"Processamento concluído — {stats['files']} arquivos, "
            f"{stats['indexed_text']} com texto indexado, {stats['duplicates']} duplicados."
        )

    def _run_search(self, query: str) -> None:
        if not query.strip():
            return
        tree = self.search_tab.search_tree  # type: ignore[attr-defined]
        tree.delete(*tree.get_children())
        results = self.case.search(query)
        for r in results:
            label = f"{r['path']} [DUPLICADO]" if r["is_duplicate"] else r["path"]
            tree.insert("", "end", values=(r["category"], label, r["snippet"]))
        self.status_var.set(f"{len(results)} resultado(s) para \"{query}\".")

    def _verify_integrity(self) -> None:
        results = []
        for item in self.case.evidence:
            ok = self.case.verify_evidence(item, actor=self.case.examiner)
            results.append(f"{item.item_id}: {'OK' if ok else 'DIVERGENTE!'}")
        messagebox.showinfo("Verificação de integridade", "\n".join(results) or "Nenhuma evidência no caso.")
        self._refresh_custody()

    def _generate_report(self) -> None:
        path = write_report(self.case)
        self.status_var.set(f"Laudo gerado: {path}")
        self._refresh_custody()
        if messagebox.askyesno("Laudo gerado", f"Laudo salvo em:\n{path}\n\nAbrir agora?"):
            self._open_file(path)

    @staticmethod
    def _open_file(path: Path) -> None:
        if sys.platform == "win32":
            os.startfile(path)  # noqa: S606
        elif sys.platform == "darwin":
            subprocess.run(["open", str(path)], check=False)
        else:
            subprocess.run(["xdg-open", str(path)], check=False)

    # ---------- refresh ----------

    def _refresh_all(self) -> None:
        self._refresh_evidence()
        self._refresh_timeline()
        self._refresh_custody()

    def _refresh_evidence(self) -> None:
        tree = self.evidence_tab.evidence_tree  # type: ignore[attr-defined]
        tree.delete(*tree.get_children())
        for item in self.case.evidence:
            tree.insert("", "end", values=(item.item_id, item.source_path, item.description,
                                            item.sha256[:16] + "…", item.added_at))

    def _refresh_timeline(self) -> None:
        tree = self.timeline_tab.timeline_tree  # type: ignore[attr-defined]
        tree.delete(*tree.get_children())

        events = self.case.timeline.sorted_events()
        types = sorted({e.event_type for e in events})
        self.event_type_filter["values"] = ["(todos)"] + types

        selected = self.event_type_filter.get()
        if selected and selected != "(todos)":
            events = [e for e in events if e.event_type == selected]

        for event in events:
            tree.insert("", "end", values=(event.timestamp, event.source_module, event.event_type, event.description))

    def _refresh_custody(self) -> None:
        tree = self.custody_tab.custody_tree  # type: ignore[attr-defined]
        tree.delete(*tree.get_children())
        for entry in self.case.custody.entries:
            tree.insert("", "end", values=(entry.timestamp, entry.actor, entry.action, entry.detail))


def main() -> None:
    app = JMToolsApp()
    app.mainloop()


if __name__ == "__main__":
    main()
