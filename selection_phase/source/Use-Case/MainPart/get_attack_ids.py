#!/usr/bin/env python
"""
Generate data/enterprise_attack_ids.txt
  • one ATT&CK technique (or sub-technique) ID per line
  • covers both Enterprise and ICS domains
"""

import os
from mitreattack.stix20 import MitreAttackData

# ───────────────────────── configuration ─────────────────────────
ENTERPRISE_STIX = "Attack-CVE-Mapping/enterprise-attack.json"
ICS_STIX        = "Attack-CVE-Mapping/ics-attack.json"
OUT_TXT         = "Use-Case/MainPart/attack_ids/enterprise_attack_ids.txt"
# ──────────────────────────────────────────────────────────────────

enterprise_data = MitreAttackData(ENTERPRISE_STIX)
ics_data        = MitreAttackData(ICS_STIX)

all_ids: set[str] = set()

def collect_ids(data_source: MitreAttackData) -> None:
    """Add every ATT&CK ID (Txxxx or Txxxx.yyy) from this domain to all_ids."""
    for obj in data_source.get_techniques(include_subtechniques=True):
        attack_id = data_source.get_attack_id(obj["id"])
        if attack_id:                            # skip deprecated/unknown
            all_ids.add(attack_id)

collect_ids(enterprise_data)
collect_ids(ics_data)

# ─────────────── optional: manual aliases (legacy names) ─────────
manual_name_aliases = {
    "data from cloud storage object": "data from cloud storage",
}
for old, new in manual_name_aliases.items():
    print(f"Legacy name '{old}' now maps to '{new}'  (IDs unchanged)")

# ───────────────────────── write the text file ───────────────────
os.makedirs(os.path.dirname(OUT_TXT), exist_ok=True)
with open(OUT_TXT, "w", encoding="utf-8") as f:
    for tid in sorted(all_ids):
        f.write(tid + "\n")

print(f" Wrote {len(all_ids)} technique IDs to '{OUT_TXT}'")
