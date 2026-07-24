#!/usr/bin/env python3
"""Download MITRE ATT&CK Enterprise STIX data and extract a compact technique index.

Fetches the full STIX bundle from mitre-attack/attack-stix-data (~50MB) and
writes only what we need to mappings/:
  - attack_techniques.json: technique id -> name/description/tactics
  - attack_tactics.json: tactic shortname -> id/name
so the MCP server never has to parse the full bundle at request time.
"""

import json
import sys
import urllib.request
from pathlib import Path

STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)
MAPPINGS_DIR = Path(__file__).resolve().parent.parent / "mappings"
TECHNIQUES_DEST_PATH = MAPPINGS_DIR / "attack_techniques.json"
TACTICS_DEST_PATH = MAPPINGS_DIR / "attack_tactics.json"


def fetch_stix_bundle() -> dict:
    print(f"Downloading {STIX_URL} ...")
    with urllib.request.urlopen(STIX_URL) as resp:
        return json.load(resp)


def extract_techniques(bundle: dict) -> dict:
    techniques = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        technique_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                break
        if not technique_id:
            continue

        tactics = [
            phase["phase_name"]
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]

        techniques[technique_id] = {
            "name": obj.get("name"),
            "description": (obj.get("description") or "").strip(),
            "tactics": tactics,
        }

    return techniques


def extract_tactics(bundle: dict) -> dict:
    tactics = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "x-mitre-tactic":
            continue

        tactic_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tactic_id = ref.get("external_id")
                break
        shortname = obj.get("x_mitre_shortname")
        if not tactic_id or not shortname:
            continue

        tactics[shortname] = {
            "id": tactic_id,
            "name": obj.get("name"),
        }

    return tactics


def main() -> int:
    bundle = fetch_stix_bundle()
    techniques = extract_techniques(bundle)
    tactics = extract_tactics(bundle)

    MAPPINGS_DIR.mkdir(parents=True, exist_ok=True)
    with TECHNIQUES_DEST_PATH.open("w", encoding="utf-8") as f:
        json.dump(techniques, f, indent=2, sort_keys=True)
    with TACTICS_DEST_PATH.open("w", encoding="utf-8") as f:
        json.dump(tactics, f, indent=2, sort_keys=True)

    print(f"Extracted {len(techniques)} techniques to {TECHNIQUES_DEST_PATH}")
    print(f"Extracted {len(tactics)} tactics to {TACTICS_DEST_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
