from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from app.core.models import Flow


class ProfileGenerator(ABC):
    @abstractmethod
    def generate(self, flows: list[Flow], output_dir: Path) -> Path:
        raise NotImplementedError
