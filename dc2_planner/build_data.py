"""Merge data/*.json into data.js for the app and report cross-reference problems.

Usage: python build_data.py [--strict]

Reads:  data/ideas.json, data/scoops.json, data/inventions.json, data/items.json, data/aliases.json (optional)
Writes: data.js (window.DC2_DATA) and stamps a content hash into sw.js so phones pick up updates.
Ideas and Scoops are merged into one 'photos' list (kind = idea|scoop). Recipe photo names and
material names are matched to photos/items by a normalized key;
anything unmatched gets a placeholder entry and is listed as a warning.
"""
import datetime
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).parent
DATA = ROOT / "data"


def slug(name):
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def key(name):
    return re.sub(r"[^a-z0-9]", "", name.lower())


def load(name, default):
    path = DATA / name
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default


def dedupe(rows, label, warnings):
    out, seen = [], {}
    for row in rows:
        row["id"] = row.get("id") or slug(row["name"])
        k = key(row["name"])
        if k in seen:
            warnings.append(f"duplicate {label}: {row['name']!r} (merged sources)")
            for field in ("sources", "refs", "recipes"):
                if row.get(field):
                    seen[k].setdefault(field, []).extend(row[field])
            continue
        seen[k] = row
        out.append(row)
    return out, seen


def main():
    warnings = []
    aliases = load("aliases.json", {"photos": {}, "items": {}})
    raw = [dict(p, kind="idea") for p in load("ideas.json", [])] + [dict(p, kind="scoop") for p in load("scoops.json", [])]
    photos, photo_index = dedupe(raw, "photo", warnings)
    items, item_index = dedupe(load("items.json", []), "item", warnings)
    inventions, inv_index = dedupe(load("inventions.json", []), "invention", warnings)

    for s in photos:
        s.setdefault("chapter", None)
        s.setdefault("missable", False)
        s.setdefault("verified", False)
    for it in items:
        it.setdefault("sources", [])

    def resolve_photo(name):
        target = aliases.get("photos", {}).get(name, name)
        hit = photo_index.get(key(target))
        if hit:
            return hit["id"]
        warnings.append(f"recipe photo not in photo list: {name!r}")
        stub = {"id": slug(target), "name": target, "category": "", "chapter": None,
                "kind": "idea", "location": "Not in photo list yet", "how": "", "missable": False,
                "missable_note": "", "sources": [], "verified": False}
        photos.append(stub)
        photo_index[key(target)] = stub
        return stub["id"]

    def resolve_item(name):
        target = aliases.get("items", {}).get(name, name)
        hit = item_index.get(key(target)) or inv_index.get(key(target))
        if hit:
            return hit["id"], hit["name"]
        warnings.append(f"material without source data: {name!r}")
        return slug(target), target

    for inv in inventions:
        inv["recipes"] = [[resolve_photo(n) for n in r] for r in inv.get("recipes", [])]
        mats = []
        for m in inv.get("materials", []):
            mid, mname = resolve_item(m["item"])
            mats.append({"id": mid, "name": mname, "qty": m.get("qty", 1)})
        inv["materials"] = mats
        inv.setdefault("verified", False)
        if not inv["recipes"]:
            warnings.append(f"invention has no recipe: {inv['name']!r}")

    payload = {
        "generated": datetime.date.today().isoformat(),
        "photos": sorted(photos, key=lambda s: s["name"].lower()),
        "inventions": sorted(inventions, key=lambda i: i["name"].lower()),
        "items": sorted(items, key=lambda i: i["name"].lower()),
    }
    (ROOT / "data.js").write_text(
        "window.DC2_DATA = " + json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + ";\n",
        encoding="utf-8")

    digest = hashlib.sha256()
    for f in ["index.html", "styles.css", "app.js", "data.js", "manifest.webmanifest"]:
        digest.update((ROOT / f).read_bytes())
    sw = ROOT / "sw.js"
    sw.write_text(re.sub(r"const VERSION = '[^']*';", f"const VERSION = '{digest.hexdigest()[:12]}';",
                         sw.read_text(encoding="utf-8")), encoding="utf-8")

    print(f"photos={len(photos)} inventions={len(inventions)} items={len(items)} warnings={len(warnings)}")
    for w in sorted(set(warnings)):
        print("  WARN", w)
    if "--strict" in sys.argv and warnings:
        sys.exit(1)


if __name__ == "__main__":
    main()
