<div align="center">

# 🛡️ CyberWatch

**A self-updating threat intelligence dashboard.**
Aggregates CVEs, advisories, incidents and IOCs from 28 sources, then tells you which handful actually need action today. Runs hourly on GitHub Actions — no servers, no cost.

[![CI](https://github.com/priyanshu965/Cyberwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/priyanshu965/Cyberwatch/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)](https://python.org)

**[→ Live dashboard](https://priyanshu965.github.io/Cyberwatch/)**

</div>

---

## What it does

Every scored item carries an **action** — *Patch now* / *Patch this week* / *Next patch cycle* / *Monitor* — blended from CVSS, EPSS, CISA KEV, public PoC availability, and SSVC decision points from CISA Vulnrichment. The score comes with a rationale you can read, not a black box.

On top of that: MITRE ATT&CK mapping, 30-day trend charts, STIX/CSV/JSON/RSS exports, Slack/Discord/Telegram/email alerts with persistent dedup, and keyboard triage (`j`/`k`/`e`/`x`/`s`, `Ctrl-K` for the command palette).

AI is used only where it beats regex: batched Gemini calls extract the affected vendor/product and write a one-line *why this matters*, plus one call per run for the daily brief. Everything else is deterministic, and the pipeline degrades to rule-based defaults if no API key is set.

## How it works

```
28 sources ──▶ fetch_intel.py ──▶ dedupe · ATT&CK · IOCs · EPSS · KEV · SSVC
                                        │
                                   compute_priority() ──▶ ACTION
                                        │
                    ┌───────────────────┴───────────────────┐
              Pages deployment                      webhook alerts
        intel.json · exports · static API              + digest
```

Two things worth knowing about the design:

- **Nothing generated is committed.** `intel.json`, the exports and the static API are published as a GitHub Pages *deployment artifact*, not pushed to the branch. State the next run needs (daily archives, health history, alert dedup) rides in the Actions cache, with a `data/state.tar.gz` published alongside the site as the recovery path. The bot never writes to the repo, so the commit count only moves when a person changes something.
- **Partial failure is fine.** A dead source is recorded in `source_health` and the run continues. Feeds still returning stale content are reported `stale`, not `ok`.

## Quick start

**Fork it.** Then Settings → Pages → Source: **GitHub Actions** (not "Deploy from a branch"), and optionally add `GEMINI_API_KEY` under Settings → Secrets → Actions. That's it — the hourly workflow does the rest.

**Run it locally:**

```bash
pip install -r requirements.txt
python scripts/fetch_intel.py     # writes data/intel.json (gitignored)
python -m http.server 8000        # → http://localhost:8000
```

Fetch before serving — a fresh clone has no `data/intel.json`, so the page would load empty.

**Docker:**

```bash
docker compose run --rm fetcher   # populate data/ first
docker compose up -d              # dashboard on :8080
```

**Tests:**

```bash
pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
```

## Configuration

Every setting lives in [`scripts/config.py`](scripts/config.py) and is overridable by environment variable. All API keys are optional — CISA Vulnrichment, the EPSS corpus and CISA KEV need no key at all.

| Variable | Default | Effect |
|---|---|---|
| `GEMINI_API_KEY` | — | Enables AI enrichment and the daily brief |
| `GROQ_API_KEY` | — | Failover if Gemini is unavailable |
| `WEBHOOK_URL` / `WEBHOOK_TYPE` | — | Alerts; leave unset to disable |
| `ALERT_SEVERITIES` | `critical` | What justifies a push (KEV/SSVC-active always alert) |
| `MAX_ITEMS_PER_SOURCE` | `10` | Per-source cap |
| `AI_ENRICH_LIMIT` | `40` | Scored items enriched per run |

Scoring weights (`PRIORITY_*`), cache TTLs (`AI_CACHE_*`), and the rest are documented inline in `config.py`.

> Never commit a key — use Actions secrets or a local `.env`. CI fails the build if a credential-shaped string appears in the tree.

## Static JSON API

Pre-rendered every run and published with the dashboard. Paths are relative to the dashboard URL.

| Endpoint | Contents |
|---|---|
| `data/intel.json` | Full feed |
| `data/api/stats.json` | Counts by severity, category, source, priority |
| `data/api/urgent.json` | Items labelled urgent or elevated |
| `data/api/exploited.json` | CISA KEV or SSVC `active` |
| `data/api/brief.json` | Today's brief |
| `data/exports/stix.json` · `feed.xml` | STIX 2.1 bundle · RSS |

---

<div align="center">

MIT · Built with GitHub Actions, Python and vanilla JS

</div>
