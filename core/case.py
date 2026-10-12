"""Gerenciamento de caso: evidências, cadeia de custódia e timeline agregada."""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from core.custody import CustodyLog, sha256_file
from core.plugin import ModuleRegistry, build_default_registry
from core.timeline import Timeline


@dataclass
class EvidenceItem:
    item_id: str
    source_path: str
    description: str
    sha256: str
    added_at: str

    def to_dict(self) -> dict:
        return {
            "item_id": self.item_id,
            "source_path": self.source_path,
            "description": self.description,
            "sha256": self.sha256,
            "added_at": self.added_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "EvidenceItem":
        return cls(**data)


class Case:
    def __init__(self, case_id: str, name: str, examiner: str, cases_dir: Path):
        self.case_id = case_id
        self.name = name
        self.examiner = examiner
        self.cases_dir = cases_dir
        self.case_dir = cases_dir / case_id
        self.evidence: list[EvidenceItem] = []
        self.custody = CustodyLog()
        self.timeline = Timeline()
        self.created_at = datetime.now(timezone.utc).isoformat()

    @property
    def manifest_path(self) -> Path:
        return self.case_dir / "case.json"

    @property
    def timeline_path(self) -> Path:
        return self.case_dir / "timeline.json"

    @classmethod
    def create(cls, name: str, examiner: str, cases_dir: Path) -> "Case":
        case_id = f"{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
        case = cls(case_id, name, examiner, cases_dir)
        case.case_dir.mkdir(parents=True, exist_ok=True)
        case.custody.record(examiner, "case_created", f"Caso '{name}' criado")
        case.save()
        return case

    @classmethod
    def load(cls, case_id: str, cases_dir: Path) -> "Case":
        case_dir = cases_dir / case_id
        manifest = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
        case = cls(case_id, manifest["name"], manifest["examiner"], cases_dir)
        case.created_at = manifest["created_at"]
        case.evidence = [EvidenceItem.from_dict(e) for e in manifest["evidence"]]
        case.custody = CustodyLog.from_dict(manifest["custody"])
        return case

    def add_evidence(self, source_path: Path, description: str, actor: str) -> EvidenceItem:
        item = EvidenceItem(
            item_id=uuid.uuid4().hex[:10],
            source_path=str(source_path),
            description=description,
            sha256=sha256_file(source_path),
            added_at=datetime.now(timezone.utc).isoformat(),
        )
        self.evidence.append(item)
        self.custody.record(
            actor,
            "evidence_added",
            f"item={item.item_id} path={source_path} sha256={item.sha256}",
        )
        self.save()
        return item

    def verify_evidence(self, item: EvidenceItem, actor: str) -> bool:
        current_hash = sha256_file(Path(item.source_path))
        ok = current_hash == item.sha256
        self.custody.record(
            actor,
            "evidence_verified" if ok else "evidence_INTEGRITY_MISMATCH",
            f"item={item.item_id} expected={item.sha256} actual={current_hash}",
        )
        self.save()
        return ok

    def run_analysis(self, registry: ModuleRegistry | None = None, actor: str = "system") -> None:
        registry = registry or build_default_registry()
        for item in self.evidence:
            path = Path(item.source_path)
            modules = registry.find_supporting(path)
            if not modules:
                self.custody.record(actor, "analysis_skipped", f"item={item.item_id} nenhum módulo compatível")
                continue
            for module in modules:
                events = module.analyze(path, item.item_id)
                self.timeline.extend(events)
                self.custody.record(
                    actor,
                    "analysis_run",
                    f"item={item.item_id} module={module.name} events={len(events)}",
                )
        self.save()

    def save(self) -> None:
        self.case_dir.mkdir(parents=True, exist_ok=True)
        manifest = {
            "case_id": self.case_id,
            "name": self.name,
            "examiner": self.examiner,
            "created_at": self.created_at,
            "evidence": [e.to_dict() for e in self.evidence],
            "custody": self.custody.to_dict(),
        }
        self.manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
        self.timeline_path.write_text(
            json.dumps(self.timeline.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8"
        )
