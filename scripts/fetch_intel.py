"""
CYBERWATCH DASHBOARD — fetch_intel.py
======================================
Fetches threat intelligence from multiple free sources:
  - NVD (NIST) CVE API        → Latest vulnerabilities
  - CISA Alerts RSS           → US government advisories
  - The Hacker News RSS       → Cybersecurity news
  - Bleeping Computer RSS     → Incidents & breaches
  - Krebs on Security RSS     → Investigative news
  - SANS ISC RSS              → Threat diaries
  - TheRecord Media RSS       → Cybersecurity news
  - Reddit r/netsec JSON      → Community intel
  - AlienVault OTX API        → Threat pulses (optional)
  - Gemini AI                 → AI summary, attack workflow, severity (optional)

Output: data/intel.json

Run manually:
  pip install requests feedparser
  python scripts/fetch_intel.py

Run via GitHub Actions: automatically on schedule (see update.yml)
"""

import json
import os
import re
import sys
import time
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests
import feedparser

# MITRE ATT&CK full database
try:
    from mitre_ttps import MITRE_TECHNIQUES, TACTIC_ORDER, map_ttps
except ImportError:
    import importlib.util, pathlib
    _spec = importlib.util.spec_from_file_location(
        "mitre_ttps",
        pathlib.Path(__file__).parent / "mitre_ttps.py"
    )
    _mod = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    MITRE_TECHNIQUES = _mod.MITRE_TECHNIQUES
    TACTIC_ORDER     = _mod.TACTIC_ORDER
    map_ttps         = _mod.map_ttps

# ─── Logging Setup ───────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("cyberwatch")

# ─── Configuration ───────────────────────────────────────────────────────────

OUTPUT_PATH         = Path("data/intel.json")
MAX_ITEMS_PER_SOURCE = 10
NVD_LOOKBACK_DAYS   = 10
REQUEST_TIMEOUT     = 30

# API Keys — set as GitHub Actions Secrets
OTX_API_KEY    = os.environ.get("OTX_API_KEY", "")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")

# How many items to enrich with Gemini (most recent first)
# Free tier: 15 RPM, so 15 items with 5s sleep = ~75s total
AI_ENRICH_LIMIT = 15
AI_SLEEP_SECS   = 4   # Sleep between Gemini calls to avoid rate limits

HEADERS = {
    "User-Agent": "CyberWatch/1.0 (GitHub personal project)"
}

# ─── RSS Feed Sources ─────────────────────────────────────────────────────────

RSS_SOURCES = [
    {
        "name":     "CISA",
        "url":      "https://www.cisa.gov/news.xml",
        "category": "advisory",
        "severity": "high",
    },
    {
        "name":     "The Hacker News",
        "url":      "https://feeds.feedburner.com/TheHackersNews",
        "category": "news",
        "severity": "medium",
    },
    {
        "name":     "Bleeping Computer",
        "url":      "https://www.bleepingcomputer.com/feed/",
        "category": "news",
        "severity": "medium",
    },
    {
        "name":     "Krebs on Security",
        "url":      "https://krebsonsecurity.com/feed/",
        "category": "news",
        "severity": "medium",
    },
    {
        "name":     "SANS ISC",
        "url":      "https://isc.sans.edu/rssfeed_full.xml",
        "category": "news",
        "severity": "low",
    },
    {
        "name":     "TheRecord Media",
        "url":      "https://therecord.media/feed",
        "category": "news",
        "severity": "high",
    },
]


# ─── Helpers ─────────────────────────────────────────────────────────────────

def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_date(date_str: str) -> str:
    if not date_str:
        return now_utc()
    try:
        if hasattr(date_str, 'tm_year'):
            dt = datetime(*date_str[:6], tzinfo=timezone.utc)
            return dt.isoformat()
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"):
            try:
                return datetime.strptime(date_str, fmt).replace(
                    tzinfo=timezone.utc
                ).isoformat()
            except ValueError:
                continue
    except Exception:
        pass
    return now_utc()


def clean_html(text: str) -> str:
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:999]


def make_request(url: str, headers: dict = None, params: dict = None,
                 method: str = "GET", json_body: dict = None) -> dict | None:
    try:
        if method == "POST":
            resp = requests.post(
                url,
                headers=headers or {"Content-Type": "application/json"},
                json=json_body,
                timeout=REQUEST_TIMEOUT
            )
        else:
            resp = requests.get(
                url,
                headers=headers or HEADERS,
                params=params,
                timeout=REQUEST_TIMEOUT
            )
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.Timeout:
        log.warning(f"Timeout: {url}")
    except requests.exceptions.HTTPError as e:
        log.warning(f"HTTP {e.response.status_code}: {url}")
    except requests.exceptions.RequestException as e:
        log.warning(f"Request failed {url}: {e}")
    except json.JSONDecodeError:
        log.warning(f"Invalid JSON from: {url}")
    return None


# ─── Fetchers ─────────────────────────────────────────────────────────────────

def fetch_rss(source: dict) -> list[dict]:
    log.info(f"Fetching RSS: {source['name']} ({source['url']})")
    items = []
    try:
        feed = feedparser.parse(source["url"])
        if feed.bozo and not feed.entries:
            log.warning(f"Feed parse error for {source['name']}: {feed.bozo_exception}")
            return items

        for entry in feed.entries[:MAX_ITEMS_PER_SOURCE]:
            title = entry.get("title", "Untitled")
            link  = entry.get("link", "")

            description = ""
            if hasattr(entry, "summary"):
                description += clean_html(entry.summary)
            elif hasattr(entry, "content"):
                description += " " + clean_html(entry.content[0].get("value", ""))
            description = description.strip()[:999]

            pub_date = parse_date(entry.get("published_parsed") or entry.get("updated_parsed"))
            severity = infer_severity(title + " " + description, source["severity"])
            category = infer_category(title + " " + description, source["category"])

            items.append({
                "title":          title,
                "description":    description,
                "url":            link,
                "cve_id":         extract_cve_id(title + " " + description),
                "source":         source["name"],
                "category":       category,
                "severity":       severity,
                "cvss_score":     None,
                "published":      pub_date,
                "ai_summary":     "",
                "workflow_graph": "",
                "severity_score": None,
            })

    except Exception as e:
        log.error(f"Unexpected error fetching {source['name']}: {e}")

    log.info(f"  Got {len(items)} items from {source['name']}")
    return items


def fetch_nvd_cves() -> list[dict]:
    log.info("Fetching CVEs from NVD API...")
    items = []

    end_date   = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=NVD_LOOKBACK_DAYS)

    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate":   end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": MAX_ITEMS_PER_SOURCE,
    }

    data = make_request("https://services.nvd.nist.gov/rest/json/cves/2.0", params=params)

    if not data:
        log.warning("NVD API returned no data")
        return items

    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")

        descriptions = cve.get("descriptions", [])
        description  = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available."
        )[:400]

        cvss_score = None
        severity   = "medium"
        metrics    = cve.get("metrics", {})

        for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data  = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                severity   = cvss_to_severity(cvss_score)
                break

        published = parse_date(cve.get("published", ""))

        items.append({
            "title":          f"{cve_id}: {description[:80]}...",
            "description":    description,
            "url":            f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "cve_id":         cve_id,
            "source":         "NVD",
            "category":       "cve",
            "severity":       severity,
            "cvss_score":     cvss_score,
            "published":      published,
            "ai_summary":     "",
            "workflow_graph": "",
            "severity_score": None,
        })

    log.info(f"  Got {len(items)} CVEs from NVD")
    return items


def fetch_reddit_netsec() -> list[dict]:
    log.info("Fetching Reddit r/netsec...")
    items = []

    headers = {**HEADERS, "User-Agent": "CyberWatch/1.0 (personal dashboard)"}
    data    = make_request("https://www.reddit.com/r/netsec.json?limit=15", headers=headers)

    if not data:
        log.warning("Reddit r/netsec returned no data")
        return items

    posts = data.get("data", {}).get("children", [])

    for post in posts:
        p = post.get("data", {})
        if p.get("stickied"):
            continue

        title     = p.get("title", "Untitled")
        url       = p.get("url", "")
        selftext  = clean_html(p.get("selftext", ""))
        created   = p.get("created_utc")
        published = datetime.fromtimestamp(created, tz=timezone.utc).isoformat() if created else now_utc()
        score     = p.get("score", 0)

        items.append({
            "title":          title,
            "description":    selftext or f"Reddit discussion (score: {score})",
            "url":            url,
            "cve_id":         extract_cve_id(title),
            "source":         "Reddit/netsec",
            "category":       infer_category(title, "news"),
            "severity":       infer_severity(title, "low"),
            "cvss_score":     None,
            "published":      published,
            "ai_summary":     "",
            "workflow_graph": "",
            "severity_score": None,
        })

    log.info(f"  Got {len(items)} posts from Reddit r/netsec")
    return items


def fetch_otx_pulse(api_key: str) -> list[dict]:
    if not api_key:
        log.info("OTX_API_KEY not set — skipping AlienVault OTX")
        return []

    log.info("Fetching AlienVault OTX pulses...")
    items = []

    headers = {**HEADERS, "X-OTX-API-KEY": api_key}
    data    = make_request(
        "https://otx.alienvault.com/api/v1/pulses/subscribed",
        headers=headers,
        params={"limit": MAX_ITEMS_PER_SOURCE}
    )

    if not data:
        log.warning("OTX API returned no data")
        return items

    for pulse in data.get("results", []):
        name        = pulse.get("name", "Untitled")
        description = (pulse.get("description") or "")[:400]
        created     = pulse.get("created", now_utc())
        pulse_id    = pulse.get("id", "")

        items.append({
            "title":          name,
            "description":    description,
            "url":            f"https://otx.alienvault.com/pulse/{pulse_id}",
            "cve_id":         None,
            "source":         "AlienVault OTX",
            "category":       "incident",
            "severity":       infer_severity(name + " " + description, "medium"),
            "cvss_score":     None,
            "published":      parse_date(created),
            "ai_summary":     "",
            "workflow_graph": "",
            "severity_score": None,
        })

    log.info(f"  Got {len(items)} pulses from AlienVault OTX")
    return items


# ─── Gemini AI Enrichment ─────────────────────────────────────────────────────

GEMINI_PROMPT_TEMPLATE = """You are a cybersecurity analyst. Analyze this threat intelligence item and respond with ONLY a valid JSON object — no markdown, no code blocks, no preamble.

Title: {title}
Description: {description}

Return exactly this JSON structure:
{{
  "ai_summary": "Two-sentence BLUF (Bottom Line Up Front): sentence 1 states what happened technically, sentence 2 states the risk and who should act.",
  "workflow_graph": "graph TD\\n    A[Initial Access] -->|method| B[Execution]\\n    B --> C[Impact]",
  "severity_score": 7.5
}}

Rules:
- ai_summary: EXACTLY 2 sentences. Technical. Actionable. No fluff.
- workflow_graph: Valid Mermaid.js graph TD. Use ATT&CK tactic names as node labels. Use --> arrows. Use |label| for edge labels where helpful. Minimum 3 nodes, maximum 7 nodes. No quotes inside node brackets.
- severity_score: Float 0.0–10.0. Base on actual impact: 9-10=critical/RCE/0day, 7-8=high/PrivEsc/DataBreach, 4-6=medium, 1-3=low/info.
- Return ONLY the JSON object."""


def enrich_with_gemini(item: dict) -> dict:
    """
    Call Gemini 1.5 Flash to add ai_summary, workflow_graph, severity_score.
    Returns the item dict with new fields populated (or empty strings on failure).
    """
    if not GEMINI_API_KEY:
        return item

    prompt = GEMINI_PROMPT_TEMPLATE.format(
        title=item.get("title", "")[:200],
        description=item.get("description", "")[:500],
    )

    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"gemini-1.5-flash:generateContent?key={GEMINI_API_KEY}"
    )

    body = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature":     0.1,
            "maxOutputTokens": 512,
            "responseMimeType": "application/json",
        },
    }

    try:
        resp = requests.post(url, json=body,
                             headers={"Content-Type": "application/json"},
                             timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()

        raw = data["candidates"][0]["content"]["parts"][0]["text"]

        # Strip markdown fences just in case model ignores responseMimeType
        raw = re.sub(r"```(?:json)?\s*", "", raw).strip().rstrip("```").strip()

        parsed = json.loads(raw)

        item["ai_summary"]     = str(parsed.get("ai_summary", "")).strip()
        item["workflow_graph"] = str(parsed.get("workflow_graph", "")).strip()
        raw_score = parsed.get("severity_score", None)
        if raw_score is not None:
            item["severity_score"] = round(float(raw_score), 1)

        log.info(f"  ✓ AI enriched: {item['title'][:60]}")

    except Exception as e:
        log.warning(f"  ✗ Gemini failed for '{item['title'][:50]}': {e}")
        # Fields already defaulted to "" / None in the item dict

    return item


# ─── Intel Inference Helpers ─────────────────────────────────────────────────

def cvss_to_severity(score: float | None) -> str:
    if score is None: return "medium"
    if score >= 9.0:  return "critical"
    if score >= 7.0:  return "high"
    if score >= 4.0:  return "medium"
    return "low"


def infer_severity(text: str, default: str = "medium") -> str:
    t = text.lower()
    if any(kw in t for kw in [
        "critical", "zero-day", "0-day", "actively exploited",
        "rce", "remote code execution", "unauthenticated", "wormable"
    ]):
        return "critical"
    if any(kw in t for kw in [
        "high", "privilege escalation", "authentication bypass",
        "ransomware", "data breach", "nation-state", "apt"
    ]):
        return "high"
    if any(kw in t for kw in [
        "medium", "xss", "csrf", "injection", "phishing", "malware"
    ]):
        return "medium"
    if any(kw in t for kw in [
        "low", "informational", "advisory", "guide", "best practice"
    ]):
        return "low"
    return default


def infer_category(text: str, default: str = "news") -> str:
    t = text.lower()
    if any(kw in t for kw in ["cve-", "vulnerability", "patch", "exploit", "nvd"]):
        return "cve"
    if any(kw in t for kw in [
        "breach", "attack", "ransomware", "hack", "intrusion",
        "stolen", "compromised", "leaked", "incident"
    ]):
        return "incident"
    if any(kw in t for kw in [
        "advisory", "alert", "directive", "guidance", "warning",
        "cisa", "recommendation", "patch tuesday"
    ]):
        return "advisory"
    return default


def extract_cve_id(text: str) -> str | None:
    match = re.search(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
    return match.group(0).upper() if match else None


def deduplicate(items: list[dict]) -> list[dict]:
    seen_titles = set()
    unique      = []
    for item in items:
        title_key = item["title"].lower().strip()[:80]
        if title_key not in seen_titles:
            seen_titles.add(title_key)
            unique.append(item)
    return unique


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    log.info("═" * 60)
    log.info("CYBERWATCH — Starting intel fetch")
    log.info("═" * 60)

    all_items = []

    # 1. RSS feeds
    for source in RSS_SOURCES:
        try:
            items = fetch_rss(source)
            all_items.extend(items)
        except Exception as e:
            log.error(f"Failed fetching {source['name']}: {e}")
        time.sleep(1)

    # 2. NVD CVE API
    try:
        all_items.extend(fetch_nvd_cves())
    except Exception as e:
        log.error(f"NVD fetch failed: {e}")
    time.sleep(1)

    # 3. Reddit r/netsec
    try:
        all_items.extend(fetch_reddit_netsec())
    except Exception as e:
        log.error(f"Reddit fetch failed: {e}")

    # 4. AlienVault OTX (optional)
    try:
        all_items.extend(fetch_otx_pulse(OTX_API_KEY))
    except Exception as e:
        log.error(f"OTX fetch failed: {e}")

    # Deduplicate
    all_items = deduplicate(all_items)

    # 5. Sort by date (newest first)
    all_items.sort(key=lambda x: x.get("published", ""), reverse=True)

    # 6. Map MITRE ATT&CK TTPs
    log.info("Mapping MITRE ATT&CK TTPs...")
    for item in all_items:
        text       = item.get("title", "") + " " + item.get("description", "")
        item["ttps"] = map_ttps(text)
    ttp_total = sum(len(i["ttps"]) for i in all_items)
    log.info(f"  Mapped {ttp_total} TTP associations across {len(all_items)} items")

    # 7. Gemini AI enrichment (top N most recent items)
    if GEMINI_API_KEY:
        log.info(f"Starting Gemini AI enrichment (top {AI_ENRICH_LIMIT} items)...")
        for i, item in enumerate(all_items[:AI_ENRICH_LIMIT]):
            enrich_with_gemini(item)
            if i < AI_ENRICH_LIMIT - 1:
                time.sleep(AI_SLEEP_SECS)  # Rate limit respect
        enriched = sum(1 for i in all_items[:AI_ENRICH_LIMIT] if i.get("ai_summary"))
        log.info(f"  AI enriched {enriched}/{min(AI_ENRICH_LIMIT, len(all_items))} items")
    else:
        log.info("GEMINI_API_KEY not set — skipping AI enrichment")

    # 8. Write output
    output = {
        "last_updated": now_utc(),
        "total_items":  len(all_items),
        "items":        all_items,
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    log.info("═" * 60)
    log.info(f"✓ Wrote {len(all_items)} items to {OUTPUT_PATH}")
    log.info("═" * 60)


if __name__ == "__main__":
    main()