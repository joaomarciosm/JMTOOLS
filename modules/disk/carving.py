"""Carving básico por assinatura de arquivo — recupera JPEG/PNG/PDF de uma
imagem de disco raw mesmo sem metadados de sistema de arquivos íntegros
(arquivo deletado cujo diretório já foi reescrito, partição não reconhecida,
etc.). Técnica clássica de perícia (igual à usada pelo motor de carving do
IPED, aqui num escopo bem menor: só 3 formatos, busca por assinatura simples
— sem reconstrução de fragmentos espalhados por múltiplas regiões).

Varre a imagem **inteira** (não só o espaço não alocado — identificar com
precisão o que está livre exigiria ler o bitmap/tabela de alocação de cada
sistema de arquivos, o que ainda não é feito aqui), então arquivos já
listados por disk.image podem aparecer de novo aqui. É lento e pode gerar
bastante ruído — por isso fica **desabilitado por padrão**
(core/config.py: disabled_modules) e o operador liga quando quiser.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from core.extraction import save_extracted_file
from core.plugin import AnalysisContext, AnalysisModule
from core.timeline import Event

RAW_EXTENSIONS = {".img", ".dd", ".raw", ".bin"}

MAX_SCAN_SIZE = 500 * 1024 * 1024  # não carrega imagens gigantes inteiras em memória
MAX_CARVED_FILE_SIZE = 20 * 1024 * 1024  # descarta "arquivo" absurdamente grande (provável falso positivo)
MAX_CARVED_FILES_PER_TYPE = 500  # trava de segurança contra imagens com milhares de falsos positivos

SIGNATURES = {
    "jpeg": {"start": b"\xff\xd8\xff", "end": b"\xff\xd9", "end_len": 2, "ext": ".jpg"},
    "png": {"start": b"\x89PNG\r\n\x1a\n", "end": b"IEND\xae\x42\x60\x82", "end_len": 8, "ext": ".png"},
    "pdf": {"start": b"%PDF-", "end": b"%%EOF", "end_len": 5, "ext": ".pdf"},
}


class CarvingModule(AnalysisModule):
    name = "disk.carving"

    def supports(self, evidence_path: Path) -> bool:
        if evidence_path.suffix.lower() in RAW_EXTENSIONS:
            return True
        try:
            with open(evidence_path, "rb") as f:
                boot_sector = f.read(512)
        except OSError:
            return False
        return len(boot_sector) == 512 and boot_sector[510:512] == b"\x55\xaa"

    def analyze(self, evidence_path: Path, evidence_item_id: str, context: AnalysisContext) -> list[Event]:
        events: list[Event] = []
        size = evidence_path.stat().st_size
        truncated = size > MAX_SCAN_SIZE

        with open(evidence_path, "rb") as f:
            data = f.read(MAX_SCAN_SIZE if truncated else size)

        if truncated:
            events.append(
                self._event(
                    evidence_item_id,
                    "carving_truncated",
                    f"Imagem maior que {MAX_SCAN_SIZE // (1024 * 1024)} MB — carving rodou só nos "
                    "primeiros bytes desse tamanho (ver docs/roadmap.md).",
                )
            )

        for file_type, sig in SIGNATURES.items():
            found = 0
            pos = 0
            while found < MAX_CARVED_FILES_PER_TYPE:
                start = data.find(sig["start"], pos)
                if start == -1:
                    break
                end_marker_pos = data.find(sig["end"], start + len(sig["start"]))
                if end_marker_pos == -1:
                    pos = start + len(sig["start"])
                    continue
                end = end_marker_pos + sig["end_len"]
                carved_size = end - start
                pos = end

                if carved_size > MAX_CARVED_FILE_SIZE or carved_size <= 0:
                    continue

                content = data[start:end]
                found += 1
                filename = f"carved_{file_type}_{start:012x}{sig['ext']}"

                if context.extracted_dir is not None:
                    save_extracted_file(context.extracted_dir, evidence_item_id, filename, content)

                events.append(
                    self._event(
                        evidence_item_id,
                        "carved_file_found",
                        f"Arquivo {file_type.upper()} recuperado por assinatura no offset {start} "
                        f"({carved_size} bytes).",
                        metadata={"type": file_type, "offset": start, "size": carved_size, "filename": filename},
                    )
                )

        return events

    def _event(self, evidence_item_id, event_type, description, metadata=None) -> Event:
        return Event(
            timestamp=datetime.now(timezone.utc).isoformat(),
            source_module=self.name,
            event_type=event_type,
            description=description,
            evidence_item_id=evidence_item_id,
            metadata=metadata or {},
        )
