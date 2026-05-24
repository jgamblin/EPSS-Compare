# EPSS-Compare

Interactive analyst report comparing **EPSS V4** (model `v2025.03.14`) to **EPSS V5 Beta** (model `v2026.05.12`) scores for the same date (2026-05-22), enriched with CVE metadata from CVEProject/cvelistV5.

## Live Report

Hosted on GitHub Pages — see the `docs/` directory.

## What It Compares

- **334,567 CVEs** scored side-by-side
- Score distributions, correlation scatter plot, and delta distribution
- Breakdown by CWE, CVSS vector components, CVSS severity, vendor, product, and CNA
- Top 50 CVEs with the largest score changes (movers)

## Key Findings (2026-05-22)

| Metric | Value |
|--------|-------|
| CVEs scored higher in V5 | **76.28%** (255,200) |
| CVEs scored lower in V5 | 14.43% (48,293) |
| Unchanged | 9.29% (31,074) |
| V4 median score | 0.00265 |
| V5 median score | 0.00766 |
| Median score shift | +0.00298 |
| Max increase | +0.97494 |
| Max decrease | −0.88379 |

## Build

```bash
pip install -r requirements.txt
python build.py --date 2026-05-22 --cve-dir ~/Data/cvelistV5
```

The build script downloads both EPSS CSV files, parses all CVE JSON metadata in parallel, computes aggregations, and writes pre-computed JSON summaries to `docs/data/`. The static `docs/index.html` loads these at runtime — no backend required.

### Options

```
--date        Score date (default: 2026-05-22)
--cve-dir     Path to CVEProject/cvelistV5 clone
--no-download Use cached CSV files from .cache/
--out-dir     Output directory (default: docs/data)
```

## GitHub Actions

The workflow (`.github/workflows/build.yml`) triggers on push to `main` and `workflow_dispatch`. It shallow-clones CVEProject/cvelistV5, runs the build, and deploys `docs/` to GitHub Pages.

To run manually with a different date:
1. Go to Actions → Build & Deploy EPSS Report → Run workflow
2. Enter the desired date in `YYYY-MM-DD` format

## Data Sources

- EPSS V4 scores: [empiricalsec/epss_scores](https://github.com/empiricalsec/epss_scores)
- EPSS V5 Beta scores: [empiricalsec/epss_scores/beta_scores/](https://github.com/empiricalsec/epss_scores/tree/main/beta_scores)
- CVE metadata: [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5)
- EPSS methodology: [FIRST.org](https://www.first.org/epss/)
