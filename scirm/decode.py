"""Error dictionary: turn any code into its meaning, likely causes, fix steps, owner and tier.

No code should reach a person without this attached. A code that is not in the dictionary is
still returned (marked unknown) so it can be alerted on and added to the issue register.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_DICTIONARY = Path(__file__).with_name("dictionary.json")
UNKNOWN_TIER = "P2"  # an unexplained error is treated as high until someone decodes it


@dataclass
class Decoded:
    key: str
    meaning: str
    causes: list[str] = field(default_factory=list)
    fix: list[str] = field(default_factory=list)
    owner: str = "Unassigned"
    category: str = "unknown"
    tier: str = UNKNOWN_TIER
    retry: bool = False
    security: bool = False
    impact: str = "Unknown"
    known: bool = True


class Dictionary:
    def __init__(self, path: Path = DEFAULT_DICTIONARY, local_codes: Path | None = None):
        data = json.loads(Path(path).read_text())
        self.tiers: dict = data["tiers"]
        self.entries: dict = data["entries"]
        # Site overlay: maps a product's own codes (e.g. 'translator:900') onto an entry,
        # or defines a full entry. Kept out of git because it describes a real system.
        self.aliases: dict[str, str] = {}
        if local_codes:
            for key, value in json.loads(Path(local_codes).read_text()).items():
                if key.startswith("_"):
                    continue
                if isinstance(value, str):
                    self.aliases[key] = value
                else:
                    self.entries[key] = value

    def canonical(self, key: str) -> str:
        """The dictionary entry a key resolves to (a site code mapped onto a shared entry)."""
        return self.aliases.get(key, key)

    def __contains__(self, key: str) -> bool:
        return self.aliases.get(key, key) in self.entries

    def decode(self, key: str) -> Decoded:
        target = self.aliases.get(key, key)
        e = self.entries.get(target)
        if e is None:
            return Decoded(
                key=key,
                meaning=f"Unknown code '{key}': not in the dictionary yet",
                fix=["Look the code up in the product's documentation or ask the vendor",
                     "Add an entry to the dictionary (or local_codes.json) once decoded"],
                owner="EDI analyst", known=False,
            )
        return Decoded(key=key, meaning=e["meaning"], causes=e.get("causes", []), fix=e.get("fix", []),
                       owner=e.get("owner", "Unassigned"), category=e.get("category", "unknown"),
                       tier=e.get("tier", UNKNOWN_TIER), retry=e.get("retry", False),
                       security=e.get("security", False), impact=e.get("impact", "Unknown"))
