#!/usr/bin/env python3
"""
One-time utility to fetch Norwegian names from SSB (Statistics Norway).

Run:  python scripts/fetch_ssb_names.py

Outputs:
  data/norwegian_first_names.txt
  data/norwegian_surnames.txt
  data/scandinavian_extra_names.txt

Uses only stdlib (urllib/json) — no extra dependencies.
"""
import json
import urllib.request
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

SSB_BASE = "https://data.ssb.no/api/v0/no/table"


def _fetch_metadata(table_id: str) -> dict:
    """GET table metadata (variables, value codes, value texts)."""
    url = f"{SSB_BASE}/{table_id}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _extract_names_from_metadata(meta: dict, variable_code: str) -> list[str]:
    """Extract human-readable name texts from a metadata variable."""
    for var in meta["variables"]:
        if var["code"] == variable_code:
            return var["valueTexts"]
    return []


def fetch_first_names() -> set[str]:
    """Fetch Norwegian first names from SSB Table 10467."""
    print("Fetching first name metadata from SSB Table 10467...")
    meta = _fetch_metadata("10467")
    raw_names = _extract_names_from_metadata(meta, "Fornavn")

    names = set()
    for name in raw_names:
        name = name.strip()
        if not name:
            continue
        # Some entries may have extra info in parentheses — strip it
        if "(" in name:
            name = name[:name.index("(")].strip()
        # Title-case if all-caps
        if name.isupper():
            name = name.title()
        # Skip entries that look like category headers or totals
        if any(w in name.lower() for w in ["alle", "total", "annet", "other", "ukjent"]):
            continue
        if len(name) >= 2:
            names.add(name)
    return names


def fetch_surnames() -> set[str]:
    """Fetch Norwegian surnames from SSB Table 12891."""
    print("Fetching surname metadata from SSB Table 12891...")
    meta = _fetch_metadata("12891")
    raw_names = _extract_names_from_metadata(meta, "Etternavn")

    names = set()
    for name in raw_names:
        name = name.strip()
        if not name:
            continue
        if "(" in name:
            name = name[:name.index("(")].strip()
        if name.isupper():
            name = name.title()
        if any(w in name.lower() for w in ["alle", "total", "annet", "other", "ukjent"]):
            continue
        if len(name) >= 2:
            names.add(name)
    return names


# Curated list of common Swedish and Danish first names that are
# absent from typical English NER models and may not appear in the
# Norwegian SSB data.
SCANDINAVIAN_EXTRA = [
    # Swedish male
    "Sven", "Gustaf", "Göran", "Lennart", "Bengt", "Gunnar", "Ingemar",
    "Bertil", "Folke", "Sixten", "Torsten", "Stellan", "Pontus", "Hampus",
    "Ludvig", "Linus", "Albin", "Melker", "Elias", "Arvid", "Birger",
    "Edvin", "Malte", "Nils", "Arne", "Sture", "Börje", "Ingvar",
    "Christer", "Conny", "Curt", "Lasse", "Mats", "Ulf", "Claes",
    "Gösta", "Håkan", "Jörgen", "Kjell", "Örjan", "Östen",
    # Swedish female
    "Birgitta", "Ingrid", "Margareta", "Kerstin", "Gudrun", "Linnéa",
    "Ebba", "Saga", "Maj", "Tyra", "Lovisa", "Elsa", "Astrid", "Freja",
    "Wilma", "Ulla", "Barbro", "Britt", "Gunilla", "Elisabet", "Beata",
    "Ylva", "Malin", "Lena", "Annika", "Elin", "Ulrika", "Josefin",
    "Mikaela", "Frida",
    # Danish male
    "Søren", "Rasmus", "Jens", "Mads", "Kasper", "Mikkel", "Nikolaj",
    "Troels", "Flemming", "Preben", "Holger", "Viggo", "Aksel", "Valdemar",
    "Svend", "Bjarne", "Mogens", "Henning", "Thorvald", "Carsten",
    "Claus", "Finn", "Kaj", "Knud", "Laurits", "Niels", "Poul",
    "Thorkild", "Torben", "Vagn",
    # Danish female
    "Bodil", "Kirsten", "Dorthe", "Inge", "Lærke", "Signe", "Nanna",
    "Mathilde", "Sofie", "Alma", "Gerda", "Dagny", "Tove", "Edith",
    "Birgit", "Grethe", "Agnete", "Else", "Karen", "Margit", "Rigmor",
    "Vibeke", "Annelise", "Dorrit", "Gurli", "Helle", "Lis", "Mette",
    "Pia", "Susanne",
    # Common Scandinavian names often missed by English NER
    "Aksel", "Anders", "Axel", "Dag", "Edvard", "Einar", "Erlend",
    "Fritjof", "Grieg", "Halvdan", "Harald", "Helge", "Henrik",
    "Ingolf", "Jørgen", "Kåre", "Kristoffer", "Ludvig", "Magnus",
    "Olav", "Peder", "Ragnar", "Sigurd", "Snorre", "Thorbjørn",
    "Thorstein", "Toralf", "Trygve", "Øyvind", "Åsmund",
    "Åsa", "Borgny", "Dagrun", "Eldrid", "Gunnvor", "Herborg",
    "Ingebjørg", "Jorunn", "Magnhild", "Oddny", "Ragnfrid",
    "Sigrun", "Solbjørg", "Torbjørg", "Tuva", "Unn", "Veslemøy",
]


def write_names(filename: str, names: set[str]) -> None:
    path = DATA_DIR / filename
    sorted_names = sorted(names, key=lambda n: n.lower())
    path.write_text("\n".join(sorted_names) + "\n", encoding="utf-8")
    print(f"  Wrote {len(sorted_names)} names to {path}")


def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    first_names = fetch_first_names()
    write_names("norwegian_first_names.txt", first_names)

    surnames = fetch_surnames()
    write_names("norwegian_surnames.txt", surnames)

    # Scandinavian extras — deduplicate against Norwegian first names
    extras = {n for n in SCANDINAVIAN_EXTRA if n not in first_names}
    write_names("scandinavian_extra_names.txt", extras)

    print(f"\nDone. Total: {len(first_names)} first names, "
          f"{len(surnames)} surnames, {len(extras)} Scandinavian extras.")


if __name__ == "__main__":
    main()
