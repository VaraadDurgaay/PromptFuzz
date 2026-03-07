"""Attack loader — reads, validates, and provides access to all attack JSON files."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console

ATTACKS_DIR = Path(__file__).parent

VALID_CATEGORIES = frozenset(
    {"jailbreak", "injection", "data_extraction", "goal_hijacking", "edge_case"}
)
VALID_SEVERITIES = frozenset({"low", "medium", "high", "critical"})
VALID_DETECTION_METHODS = frozenset({"keyword", "regex", "refusal", "length"})
VALID_SUCCESS_IF = frozenset(
    {"any_present", "all_present", "none_present", "refusal_absent"}
)

ATTACK_FILES: dict[str, Path] = {
    "jailbreak": ATTACKS_DIR / "jailbreaks.json",
    "injection": ATTACKS_DIR / "injections.json",
    "data_extraction": ATTACKS_DIR / "data_extraction.json",
    "goal_hijacking": ATTACKS_DIR / "goal_hijacking.json",
    "edge_case": ATTACKS_DIR / "edge_cases.json",
}

_console = Console(stderr=True)


@dataclass(frozen=True)
class DetectionConfig:
    """Detection configuration for a single attack."""

    method: str
    indicators: list[str]
    success_if: str


@dataclass(frozen=True)
class Attack:
    """Represents a single adversarial attack definition."""

    id: str
    name: str
    category: str
    severity: str
    description: str
    prompt: str
    detection: DetectionConfig
    tags: list[str]
    remediation: str


class AttackLoader:
    """Loads and validates attack definitions from JSON files."""

    def load_all(self) -> list[Attack]:
        """Load every attack from all five category files.

        Returns:
            List of all Attack objects across all categories.
        """
        attacks: list[Attack] = []
        for category in VALID_CATEGORIES:
            attacks.extend(self.load_category(category))
        return attacks

    def load_category(self, category: str) -> list[Attack]:
        """Load attacks for a single category.

        Args:
            category: One of the valid category strings.

        Returns:
            List of Attack objects for that category.

        Raises:
            ValueError: If the category is not recognised.
        """
        if category not in VALID_CATEGORIES:
            raise ValueError(
                f"Unknown category '{category}'. "
                f"Valid categories: {sorted(VALID_CATEGORIES)}"
            )
        path = ATTACK_FILES[category]
        return self._load_file(path)

    def load_categories(self, categories: list[str]) -> list[Attack]:
        """Load attacks for a subset of categories.

        Args:
            categories: List of category strings to load.

        Returns:
            Combined list of Attack objects for all requested categories.
        """
        attacks: list[Attack] = []
        for category in categories:
            attacks.extend(self.load_category(category))
        return attacks

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _load_file(self, path: Path) -> list[Attack]:
        """Read a JSON file and parse every entry into an Attack dataclass."""
        if not path.exists():
            _console.print(
                f"[bold red]Error:[/bold red] Attack file not found: {path}"
            )
            return []

        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            _console.print(
                f"[bold red]Error:[/bold red] Cannot read {path}: {exc}"
            )
            return []

        try:
            data: list[dict] = json.loads(raw)
        except json.JSONDecodeError as exc:
            _console.print(
                f"[bold red]Error:[/bold red] Invalid JSON in {path}: {exc}"
            )
            return []

        attacks: list[Attack] = []
        for entry in data:
            try:
                attacks.append(self.validate_attack(entry))
            except (KeyError, ValueError, TypeError) as exc:
                attack_id = entry.get("id", "<unknown>")
                _console.print(
                    f"[bold yellow]Warning:[/bold yellow] Skipping invalid "
                    f"attack {attack_id} in {path.name}: {exc}"
                )
        return attacks

    def validate_attack(self, data: dict) -> Attack:
        """Validate a raw dict against the attack schema and return an Attack.

        Args:
            data: Raw dict parsed from JSON.

        Returns:
            Validated Attack dataclass instance.

        Raises:
            KeyError: If a required field is missing.
            ValueError: If a field value is not in the allowed set.
            TypeError: If a field has the wrong type.
        """
        required = {
            "id", "name", "category", "severity",
            "description", "prompt", "detection", "tags", "remediation",
        }
        missing = required - data.keys()
        if missing:
            raise KeyError(f"Missing required fields: {missing}")

        category = data["category"]
        if category not in VALID_CATEGORIES:
            raise ValueError(
                f"Invalid category '{category}'. "
                f"Must be one of {sorted(VALID_CATEGORIES)}"
            )

        severity = data["severity"]
        if severity not in VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity '{severity}'. "
                f"Must be one of {sorted(VALID_SEVERITIES)}"
            )

        det = data["detection"]
        if not isinstance(det, dict):
            raise TypeError("'detection' must be a dict")

        method = det.get("method", "")
        if method not in VALID_DETECTION_METHODS:
            raise ValueError(
                f"Invalid detection method '{method}'. "
                f"Must be one of {sorted(VALID_DETECTION_METHODS)}"
            )

        success_if = det.get("success_if", "")
        if success_if not in VALID_SUCCESS_IF:
            raise ValueError(
                f"Invalid success_if '{success_if}'. "
                f"Must be one of {sorted(VALID_SUCCESS_IF)}"
            )

        if not isinstance(det.get("indicators", []), list):
            raise TypeError("'detection.indicators' must be a list")

        if not isinstance(data["tags"], list):
            raise TypeError("'tags' must be a list")

        detection = DetectionConfig(
            method=method,
            indicators=det.get("indicators", []),
            success_if=success_if,
        )

        return Attack(
            id=str(data["id"]),
            name=str(data["name"]),
            category=category,
            severity=severity,
            description=str(data["description"]),
            prompt=str(data["prompt"]),
            detection=detection,
            tags=list(data["tags"]),
            remediation=str(data["remediation"]),
        )
