"""Local Scan Storage & History Repository for ShieldScan.
Persists canonical ScanResult assessments as JSON for auditing and comparison.
"""

from __future__ import annotations
import glob
import json
import os
from pathlib import Path
from typing import List, Optional
from src.models.assessment import ScanResult

DEFAULT_STORAGE_DIR = Path("C:/Users/tejas/.gemini/antigravity-ide/scratch/ShieldScan/exports/json")


class ScanStore:
    """Manages persistence and retrieval of historical scan assessments."""

    def __init__(self, storage_dir: Optional[Path] = None):
        self.storage_dir = storage_dir or DEFAULT_STORAGE_DIR
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def save(self, scan_result: ScanResult) -> Path:
        """Saves a ScanResult as a JSON file."""
        filename = f"{scan_result.id}_{scan_result.started_at.replace(':', '-').replace('.', '_')}.json"
        filepath = self.storage_dir / filename
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(scan_result.to_json(indent=2))
        return filepath

    def get_by_id(self, scan_id: str) -> Optional[ScanResult]:
        """Loads a specific scan result by its ID."""
        for path in self.storage_dir.glob("*.json"):
            if path.name.startswith(f"{scan_id}_") or path.stem == scan_id:
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        return ScanResult.from_json(f.read())
                except Exception:
                    continue
        return None

    def list_all(self) -> List[ScanResult]:
        """Loads all historical scan assessments, sorted newest first."""
        results: List[ScanResult] = []
        for path in sorted(self.storage_dir.glob("*.json"), key=os.path.getmtime, reverse=True):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    results.append(ScanResult.from_json(f.read()))
            except Exception:
                continue
        return results

    def get_latest(self) -> Optional[ScanResult]:
        """Returns the most recently recorded scan assessment."""
        all_scans = self.list_all()
        return all_scans[0] if all_scans else None
