# DC2 Invention Planner

A Dark Cloud 2 (Dark Chronicle) planner for photos and inventions. It runs as a static web page and works offline once installed on a phone.

## What it does

- **Inventions:** everything you can build up to your chapter. Each one is marked Ready (you have all 3 photos), 1 away, or Invented. Its page shows every recipe, the photos with where to take them, and the materials with where to get them.
- **Photos:** Ideas and Scoops sorted by how many inventions you haven't made yet each one helps with. Tap a photo to see what it's used in.
- **Checklist:** every Idea and Scoop grouped by chapter, with filters for Missable only and Hide taken.
- **Progress:** totals, plus export and import of your progress as a JSON backup.

Progress is saved in your browser (localStorage), so export it now and then.

## Data

The source data is in `data/` and each entry lists its source URLs in `sources`. Chapters, recipes, materials and missable flags come from Dark Ryder's [Photography and Invention Guide](https://gamefaqs.gamespot.com/ps2/561438-dark-cloud-2/faqs/21897) on GameFAQs. Location notes and material sources come from the Dark Cloud wiki and Almar's Guides. A photo marked `maybe_missable` is one that another guide calls missable but Dark Ryder's doesn't.

| File | Contents |
| --- | --- |
| `ideas.json` | Photo Ideas, the things inventions are made from |
| `scoops.json` | The 54 Scoops from the Scoop memo (several are missable) |
| `inventions.json` | Inventions with their 3-photo recipes and materials |
| `items.json` | Where to get each material |
| `aliases.json` | Optional: maps different spellings to one name, e.g. `{"photos": {"Hmmm! Jurak": "Hmmmm! Jurak"}, "items": {}}` |

Entries marked `verified: false` were missing details or had conflicting sources. To fix one, edit the JSON and rebuild:

```bash
python dc2_planner/build_data.py
```

This writes `data.js` and bumps the offline cache version. It also lists any recipe photos or materials it couldn't match, which usually means a spelling difference that needs an alias.

## Running and deploying

- **Locally:** open `index.html` directly, or run `python -m http.server` in this folder.
- **Hosted:** `.github/workflows/dc2-planner-pages.yml` deploys this folder to GitHub Pages on every push to `main` that touches it. Repo Settings → Pages → Source must be set to **GitHub Actions**.
- **Phone:** open the Pages URL once while online, then use Add to Home Screen. After that it works offline.
