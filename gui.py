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

from core import ocr
from core.case import Case
from core.graph import circular_layout
from reports.generator import write_report

try:
    from PIL import Image, ImageTk

    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

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
        ttk.Button(toolbar, text="⚙ Configurações", command=self._open_config_dialog).pack(side="left", padx=2)

        self.status_var = tk.StringVar(value="Pronto.")
        ttk.Label(self, textvariable=self.status_var, style="SubHeader.TLabel").pack(anchor="w", pady=(0, 4))

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True)

        self.evidence_tab = self._build_evidence_tab(notebook)
        self.timeline_tab = self._build_timeline_tab(notebook)
        self.search_tab = self._build_search_tab(notebook)
        self.gallery_tab = self._build_gallery_tab(notebook)
        self.graph_tab = self._build_graph_tab(notebook)
        self.custody_tab = self._build_custody_tab(notebook)
        notebook.add(self.evidence_tab, text="Evidências")
        notebook.add(self.timeline_tab, text="Timeline")
        notebook.add(self.search_tab, text="Busca")
        notebook.add(self.gallery_tab, text="Galeria")
        notebook.add(self.graph_tab, text="Grafo")
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
        ttk.Button(bar, text="🔎 Padrões sensíveis (PII)", command=self._show_pii_report).pack(side="left", padx=10)
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
        tree.bind("<Double-1>", self._open_search_result)
        frame.search_tree = tree  # type: ignore[attr-defined]
        frame.query_var = query_var  # type: ignore[attr-defined]
        return frame

    def _build_gallery_tab(self, parent) -> ttk.Frame:
        frame = ttk.Frame(parent, padding=8)
        bar = ttk.Frame(frame)
        bar.pack(fill="x", pady=(0, 6))
        ttk.Button(bar, text="🔄 Atualizar galeria", command=self._refresh_gallery).pack(side="left")
        ttk.Label(
            bar, text="Clique duas vezes numa miniatura para abrir a imagem — "
                      "imagens próximas na galeria tendem a ser do mesmo cluster de similaridade.",
            style="SubHeader.TLabel",
        ).pack(side="left", padx=10)

        canvas = tk.Canvas(frame, highlightthickness=0)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        inner = ttk.Frame(canvas)
        inner.bind("<Configure>", lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        frame.gallery_canvas = canvas  # type: ignore[attr-defined]
        frame.gallery_inner = inner  # type: ignore[attr-defined]
        frame.thumbnails = []  # type: ignore[attr-defined]  # mantém referência viva (Tkinter não segura PhotoImage sozinho)
        return frame

    def _build_graph_tab(self, parent) -> ttk.Frame:
        frame = ttk.Frame(parent, padding=8)
        bar = ttk.Frame(frame)
        bar.pack(fill="x", pady=(0, 6))
        ttk.Button(bar, text="🔄 Atualizar grafo", command=self._refresh_graph).pack(side="left")
        ttk.Label(
            bar, text="Contatos a partir de SMS, chamadas, WhatsApp e histórico de navegador já analisados.",
            style="SubHeader.TLabel",
        ).pack(side="left", padx=10)

        canvas = tk.Canvas(frame, background="white", highlightthickness=1, highlightbackground="#ccc")
        canvas.pack(fill="both", expand=True)
        frame.graph_canvas = canvas  # type: ignore[attr-defined]
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
        self._search_result_paths = {}
        results = self.case.search(query)
        for r in results:
            label = f"{r['path']} [DUPLICADO]" if r["is_duplicate"] else r["path"]
            item_id = tree.insert("", "end", values=(r["category"], label, r["snippet"]))
            self._search_result_paths[item_id] = self.case.extracted_dir / r["path"]
        self.status_var.set(f"{len(results)} resultado(s) para \"{query}\".")

    def _open_search_result(self, _event=None) -> None:
        tree = self.search_tab.search_tree  # type: ignore[attr-defined]
        selection = tree.selection()
        if not selection:
            return
        path = getattr(self, "_search_result_paths", {}).get(selection[0])
        if not path or not path.exists():
            messagebox.showinfo("Arquivo não encontrado", "O arquivo não está mais disponível em disco.")
            return
        FileViewerWindow(self, path)

    def _show_pii_report(self) -> None:
        hits = self.case.pii_report()
        if not hits:
            messagebox.showinfo("Padrões sensíveis", "Nenhum padrão encontrado (rode \"Processar/Indexar\" antes).")
            return
        tree = self.search_tab.search_tree  # type: ignore[attr-defined]
        tree.delete(*tree.get_children())
        self._search_result_paths = {}
        for h in hits:
            item_id = tree.insert("", "end", values=(h["type"], h["path"], h["value"]))
            self._search_result_paths[item_id] = self.case.extracted_dir / h["path"]
        self.status_var.set(f"{len(hits)} padrão(ões) sensível(eis) encontrado(s).")

    def _refresh_gallery(self) -> None:
        tab = self.gallery_tab
        for widget in tab.gallery_inner.winfo_children():  # type: ignore[attr-defined]
            widget.destroy()
        tab.thumbnails.clear()  # type: ignore[attr-defined]

        if not PIL_AVAILABLE:
            ttk.Label(tab.gallery_inner, text="Pillow não está instalado — galeria indisponível.").pack()  # type: ignore[attr-defined]
            return

        image_paths = sorted(
            p for p in self.case.extracted_dir.rglob("*")
            if p.is_file() and p.suffix.lower() in (".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp")
        )
        if not image_paths:
            ttk.Label(
                tab.gallery_inner,  # type: ignore[attr-defined]
                text="Nenhuma imagem extraída ainda (rode Analisar / Processar/Indexar antes).",
            ).pack()
            return

        columns = 6
        for i, path in enumerate(image_paths):
            try:
                with Image.open(path) as img:
                    img.thumbnail((120, 120))
                    photo = ImageTk.PhotoImage(img)
            except Exception:  # noqa: BLE001 — imagem corrompida/ilegível só fica sem miniatura
                continue
            tab.thumbnails.append(photo)  # type: ignore[attr-defined]
            btn = tk.Button(
                tab.gallery_inner, image=photo, command=lambda p=path: self._open_file(p), relief="flat",  # type: ignore[attr-defined]
            )
            btn.grid(row=i // columns, column=i % columns, padx=4, pady=4)

        self.status_var.set(f"{len(image_paths)} imagem(ns) na galeria.")

    def _refresh_graph(self) -> None:
        canvas = self.graph_tab.graph_canvas  # type: ignore[attr-defined]
        canvas.delete("all")
        counts = self.case.contact_counts()
        if not counts:
            canvas.create_text(
                200, 100, text="Nenhum contato encontrado (rode Analisar antes).", anchor="nw"
            )
            return

        top_contacts = list(counts.items())[:25]  # limite visual — grafos com centenas de nós viram ilegíveis
        contacts = [c for c, _ in top_contacts]
        max_count = max(counts.values())

        canvas.update_idletasks()
        cx, cy = max(canvas.winfo_width(), 500) / 2, max(canvas.winfo_height(), 500) / 2
        radius = min(cx, cy) - 80
        positions = circular_layout(contacts, center=(cx, cy), radius=radius)

        center_pos = positions["__center__"]
        canvas.create_oval(
            center_pos[0] - 20, center_pos[1] - 20, center_pos[0] + 20, center_pos[1] + 20, fill="#4a90d9"
        )
        canvas.create_text(center_pos[0], center_pos[1], text="Caso", fill="white")

        for contact, count in top_contacts:
            x, y = positions[contact]
            width = 1 + round(4 * count / max_count)
            canvas.create_line(center_pos[0], center_pos[1], x, y, width=width, fill="#999")
            node_radius = 10 + round(15 * count / max_count)
            canvas.create_oval(
                x - node_radius, y - node_radius, x + node_radius, y + node_radius, fill="#e07a5f"
            )
            canvas.create_text(x, y + node_radius + 10, text=f"{contact}\n({count})", font=("Segoe UI", 8))

    def _open_config_dialog(self) -> None:
        ConfigDialog(self, self.case)

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


TEXT_PREVIEW_EXTENSIONS = {".txt", ".json", ".xml", ".csv", ".html", ".htm", ".log", ".md", ".plist"}


class FileViewerWindow(tk.Toplevel):
    """Visualizador simples: texto decodificado para arquivos de texto,
    dump hexadecimal para o resto — inspirado nos visualizadores embutidos
    do IPED (hex/texto/nativo), numa versão bem mais simples."""

    MAX_PREVIEW_BYTES = 256 * 1024

    def __init__(self, parent: tk.Widget, path: Path) -> None:
        super().__init__(parent)
        self.title(f"Visualizar — {path.name}")
        self.geometry("800x600")

        text_widget = tk.Text(self, font=("Consolas", 10), wrap="none")
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=text_widget.yview)
        text_widget.configure(yscrollcommand=scrollbar.set)
        text_widget.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        data = path.read_bytes()[: self.MAX_PREVIEW_BYTES]
        if path.suffix.lower() in TEXT_PREVIEW_EXTENSIONS:
            content = data.decode("utf-8", errors="replace")
        else:
            content = self._hex_dump(data)
        if len(path.read_bytes()) > self.MAX_PREVIEW_BYTES:
            content += f"\n\n[... arquivo truncado, mostrando só os primeiros {self.MAX_PREVIEW_BYTES} bytes ...]"

        text_widget.insert("1.0", content)
        text_widget.configure(state="disabled")

    @staticmethod
    def _hex_dump(data: bytes, width: int = 16) -> str:
        lines = []
        for offset in range(0, len(data), width):
            chunk = data[offset: offset + width]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{offset:08x}  {hex_part:<{width * 3}}  {ascii_part}")
        return "\n".join(lines)


class ConfigDialog(tk.Toplevel):
    """Edição da configuração do caso (core/config.py) — tudo aqui é
    "configurável pelo operador", gravado em case/config.json."""

    def __init__(self, parent: tk.Widget, case: Case) -> None:
        super().__init__(parent)
        self.case = case
        self.title("Configurações do caso")
        self.geometry("520x480")

        frame = ttk.Frame(self, padding=12)
        frame.pack(fill="both", expand=True)

        row = 0
        self.carving_var = tk.BooleanVar(value="disk.carving" not in case.config.disabled_modules)
        ttk.Checkbutton(
            frame, text="Habilitar carving (recuperação de JPEG/PNG/PDF por assinatura — lento)",
            variable=self.carving_var,
        ).grid(row=row, column=0, columnspan=2, sticky="w", pady=4)
        row += 1

        self.pii_var = tk.BooleanVar(value=case.config.pii_scan_enabled)
        ttk.Checkbutton(frame, text="Buscar padrões sensíveis (PII) no processamento", variable=self.pii_var).grid(
            row=row, column=0, columnspan=2, sticky="w", pady=4
        )
        row += 1

        self.clustering_var = tk.BooleanVar(value=case.config.image_clustering_enabled)
        ttk.Checkbutton(
            frame, text="Agrupar imagens semelhantes (hash perceptual)", variable=self.clustering_var
        ).grid(row=row, column=0, columnspan=2, sticky="w", pady=4)
        row += 1

        self.ocr_var = tk.BooleanVar(value=case.config.ocr_enabled)
        ocr_note = "" if ocr.is_available() else "  (Tesseract não encontrado no PATH)"
        ttk.Checkbutton(frame, text=f"OCR em imagens via Tesseract{ocr_note}", variable=self.ocr_var).grid(
            row=row, column=0, columnspan=2, sticky="w", pady=4
        )
        row += 1

        ttk.Label(frame, text="Tamanho máximo de arquivo extraído (MB):").grid(row=row, column=0, sticky="w", pady=(12, 4))
        self.max_size_var = tk.IntVar(value=case.config.max_extract_size_mb)
        ttk.Entry(frame, textvariable=self.max_size_var, width=10).grid(row=row, column=1, sticky="w", pady=(12, 4))
        row += 1

        ttk.Label(frame, text="Palavras-chave de destaque (separadas por vírgula):").grid(
            row=row, column=0, columnspan=2, sticky="w", pady=(12, 4)
        )
        row += 1
        self.keywords_var = tk.StringVar(value=", ".join(case.config.keywords))
        ttk.Entry(frame, textvariable=self.keywords_var, width=60).grid(row=row, column=0, columnspan=2, sticky="we")
        row += 1

        ttk.Label(frame, text="Lista de hashes conhecidos/ignorados (arquivo, opcional):").grid(
            row=row, column=0, columnspan=2, sticky="w", pady=(12, 4)
        )
        row += 1
        self.known_hash_var = tk.StringVar(value=case.config.known_hash_ignore_file or "")
        path_frame = ttk.Frame(frame)
        path_frame.grid(row=row, column=0, columnspan=2, sticky="we")
        ttk.Entry(path_frame, textvariable=self.known_hash_var, width=48).pack(side="left")
        ttk.Button(path_frame, text="...", width=3, command=self._pick_hash_file).pack(side="left", padx=4)
        row += 1

        ttk.Button(frame, text="Salvar", command=self._save).grid(row=row, column=0, pady=20, sticky="w")
        ttk.Button(frame, text="Cancelar", command=self.destroy).grid(row=row, column=1, pady=20, sticky="w")

    def _pick_hash_file(self) -> None:
        path = filedialog.askopenfilename(title="Selecionar lista de hashes conhecidos (um SHA-256 por linha)")
        if path:
            self.known_hash_var.set(path)

    def _save(self) -> None:
        config = self.case.config
        config.disabled_modules = [] if self.carving_var.get() else ["disk.carving"]
        config.pii_scan_enabled = self.pii_var.get()
        config.image_clustering_enabled = self.clustering_var.get()
        config.ocr_enabled = self.ocr_var.get()
        config.max_extract_size_mb = self.max_size_var.get()
        config.keywords = [k.strip() for k in self.keywords_var.get().split(",") if k.strip()]
        config.known_hash_ignore_file = self.known_hash_var.get().strip() or None
        config.save(self.case.config_path)
        messagebox.showinfo("Configurações salvas", "Configurações salvas. Rode Analisar/Processar novamente para aplicar.")
        self.destroy()


def main() -> None:
    app = JMToolsApp()
    app.mainloop()


if __name__ == "__main__":
    main()
