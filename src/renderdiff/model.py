from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Any

@dataclass(frozen=True)
class Finding:
    id: str
    category: str
    severity: str
    materiality: str
    start: int | None
    end: int | None
    evidence: dict[str, Any]
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
