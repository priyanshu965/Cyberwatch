"""
CYBERWATCH DASHBOARD — fetch_intel.py
======================================
Fetches threat intelligence from multiple free sources:
- NVD (NIST) CVE API     → Latest vulnerabilities
- CISA Alerts RSS         → US government advisories
- The Hacker News RSS     → Cybersecurity news
- Bleeping Computer RSS   → Incidents & breaches
- Krebs on Security RSS   → Investigative news
- SANS ISC RSS            → Threat diaries
- Reddit r/netsec JSON    → Community intel
- AlienVault OTX API      → Threat pulse (if API key set)

NEW: Gemini AI enrichment for top 15 items:
  - ai_summary      : 2-sentence BLUF analysis
  - workflow_graph  : Mermaid.js graph TD attack chain
  - severity_score  : Float 0.0–10.0

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

# MITRE ATT&CK full database (246 techniques + 445 sub-techniques)
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

OUTPUT_PATH          = Path("data/intel.json")
MAX_ITEMS_PER_SOURCE = 10
NVD_LOOKBACK_DAYS    = 10
REQUEST_TIMEOUT      = 30

# How many of the most-recent items to enrich via Gemini
GEMINI_ENRICH_TOP_N  = 15

# API keys — set as GitHub Actions Secrets
OTX_API_KEY    = os.environ.get("OTX_API_KEY",    "")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")

HEADERS = {"User-Agent": "CyberWatch/1.0 (GitHub personal project)"}

# ─── RSS Feed Sources ─────────────────────────────────────────────────────────

RSS_SOURCES = [
    {"name": "CISA",            "url": "https://www.cisa.gov/news.xml",                        "category": "advisory", "severity": "high"},
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews",           "category": "news",     "severity": "medium"},
    {"name": "Bleeping Computer","url": "https://www.bleepingcomputer.com/feed/",               "category": "news",     "severity": "medium"},
    {"name": "Krebs on Security","url": "https://krebsonsecurity.com/feed/",                    "category": "news",     "severity": "medium"},
    {"name": "SANS ISC",        "url": "https://isc.sans.edu/rssfeed_full.xml",                "category": "news",     "severity": "low"},
    {"name": "TheRecord Media", "url": "https://therecord.media/feed",                         "category": "news",     "severity": "high"},
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
                return datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc).isoformat()
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

def make_request(url: str, headers: dict = None, params: dict = None) -> dict | None:
    try:
        resp = requests.get(url, headers=headers or HEADERS, params=params, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.Timeout:
        log.warning(f"Timeout fetching: {url}")
    except requests.exceptions.HTTPError as e:
        log.warning(f"HTTP error {e.response.status_code} for: {url}")
    except requests.exceptions.RequestException as e:
        log.warning(f"Request failed for {url}: {e}")
    except json.JSONDecodeError:
        log.warning(f"Invalid JSON from: {url}")
    return None

# ─── Gemini AI Enrichment ─────────────────────────────────────────────────────

def call_gemini(title: str, description: str, api_key: str) -> dict | None:
    """
    Call Gemini 2.0 Flash to produce AI analysis for a threat intel item.
    Returns a dict with keys: ai_summary, workflow_graph, severity_score.
    Returns None on any failure so the caller can gracefully skip enrichment.
    """
    prompt = (
        "You are a senior cybersecurity analyst. Analyze this threat intelligence item "
        "and respond with ONLY a valid JSON object — no markdown, no code fences, no extra text.\n\n"
        f"Title: {title}\n"
        f"Description: {description[:600]}\n\n"
        "Return exactly this JSON structure:\n"
        "{\n"
        '  "ai_summary": "First sentence: state the core threat/impact. Second sentence: state the affected systems/actors/mitigations.",\n'
        '  "workflow_graph": "graph TD\\n  A[Initial Access] --> B[Execution]\\n  B --> C[Persistence]\\n  C --> D[Exfiltration]",\n'
        '  "severity_score": 7.5\n'
        "}\n\n"
        "Rules:\n"
        "- ai_summary: EXACTLY 2 sentences. Technical BLUF. Specific, not generic.\n"
        "- workflow_graph: Valid Mermaid.js graph TD. 3–6 nodes using realistic MITRE ATT&CK tactic names "
        "(e.g. Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, "
        "Credential Access, Discovery, Lateral Movement, Collection, Exfiltration, Impact). "
        "Use short labels. Escape any special chars. No subgraphs.\n"
        "- severity_score: Float 0.0–10.0. 9–10=Critical, 7–8=High, 4–6=Medium, 1–3=Low, 0=Informational.\n"
    )

    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"gemini-2.0-flash:generateContent?key={api_key}"
    )
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 600,
        },
    }

    try:
        resp = requests.post(url, json=payload, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        raw_text = data["candidates"][0]["content"]["parts"][0]["text"].strip()

        # Strip any accidental markdown fences
        raw_text = re.sub(r"^```(?:json)?\s*", "", raw_text, flags=re.MULTILINE)
        raw_text = re.sub(r"\s*```$",           "", raw_text, flags=re.MULTILINE)

        result = json.loads(raw_text)

        # Validate required keys and types
        ai_summary     = str(result.get("ai_summary", "")).strip()
        workflow_graph = str(result.get("workflow_graph", "")).strip()
        severity_score = result.get("severity_score")

        if isinstance(severity_score, (int, float)):
            severity_score = round(float(max(0.0, min(10.0, severity_score))), 1)
        else:
            severity_score = None

        return {
            "ai_summary":     ai_summary     or None,
            "workflow_graph": workflow_graph  or None,
            "severity_score": severity_score,
        }

    except (requests.exceptions.RequestException, KeyError, json.JSONDecodeError, IndexError) as e:
        log.warning(f"Gemini enrichment failed: {e}")
        return None


def enrich_with_gemini(items: list[dict], api_key: str) -> None:
    """
    In-place enrichment of the top GEMINI_ENRICH_TOP_N items (by published date).
    Skips gracefully if api_key is not set or any individual call fails.
    Adds ai_summary, workflow_graph, and severity_score keys to each item.
    """
    if not api_key:
        log.info("GEMINI_API_KEY not set — skipping AI enrichment")
        for item in items:
            item.setdefault("ai_summary",     None)
            item.setdefault("workflow_graph",  None)
            item.setdefault("severity_score",  None)
        return

    top_items  = items[:GEMINI_ENRICH_TOP_N]
    rest_items = items[GEMINI_ENRICH_TOP_N:]

    log.info(f"Enriching top {len(top_items)} items with Gemini AI...")

    for i, item in enumerate(top_items):
        title       = item.get("title", "")
        description = item.get("description", "")
        log.info(f"  [{i+1}/{len(top_items)}] Calling Gemini for: {title[:60]}...")

        result = call_gemini(title, description, api_key)
        if result:
            item["ai_summary"]     = result.get("ai_summary")
            item["workflow_graph"] = result.get("workflow_graph")
            item["severity_score"] = result.get("severity_score")
            log.info(f"    ✓ Score={item['severity_score']}  summary={str(item['ai_summary'])[:60]}...")
        else:
            item["ai_summary"]     = None
            item["workflow_graph"] = None
            item["severity_score"] = None

        # Respect Gemini free-tier rate limit (~15 RPM)
        if i < len(top_items) - 1:
            time.sleep(4)

    # Ensure all remaining items have the new fields (as null)
    for item in rest_items:
        item.setdefault("ai_summary",     None)
        item.setdefault("workflow_graph",  None)
        item.setdefault("severity_score",  None)

    log.info(f"  AI enrichment complete for {len(top_items)} items")


# ─── Fetchers ────────────────────────────────────────────────────────────────

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
                "title":       title,
                "description": description,
                "url":         link,
                "cve_id":      extract_cve_id(title + " " + description),
                "source":      source["name"],
                "category":    category,
                "severity":    severity,
                "cvss_score":  None,
                "published":   pub_date,
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
        "pubStartDate":    start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate":      end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage":  MAX_ITEMS_PER_SOURCE,
    }

    data = make_request("https://services.nvd.nist.gov/rest/json/cves/2.0", params=params)
    if not data:
        log.warning("NVD API returned no data")
        return items

    for vuln in data.get("vulnerabilities", []):
        cve        = vuln.get("cve", {})
        cve_id     = cve.get("id", "")
        descs      = cve.get("descriptions", [])
        description = next((d["value"] for d in descs if d.get("lang") == "en"),
                          "No description available.")[:400]

        cvss_score = None
        severity   = "medium"
        metrics    = cve.get("metrics", {})
        for mk in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            ml = metrics.get(mk, [])
            if ml:
                cvss_score = ml[0].get("cvssData", {}).get("baseScore")
                severity   = cvss_to_severity(cvss_score)
                break

        items.append({
            "title":       f"{cve_id}: {description[:80]}...",
            "description": description,
            "url":         f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "cve_id":      cve_id,
            "source":      "NVD",
            "category":    "cve",
            "severity":    severity,
            "cvss_score":  cvss_score,
            "published":   parse_date(cve.get("published", "")),
        })

    log.info(f"  Got {len(items)} CVEs from NVD")
    return items


def fetch_reddit_netsec() -> list[dict]:
    log.info("Fetching Reddit r/netsec...")
    items = []
    hdrs  = {**HEADERS, "User-Agent": "CyberWatch/1.0 (personal dashboard)"}
    data  = make_request("https://www.reddit.com/r/netsec.json?limit=15", headers=hdrs)
    if not data:
        log.warning("Reddit r/netsec returned no data")
        return items

    for post in data.get("data", {}).get("children", []):
        p = post.get("data", {})
        if p.get("stickied"):
            continue
        title    = p.get("title", "Untitled")
        url      = p.get("url", "")
        selftext = clean_html(p.get("selftext", ""))
        created  = p.get("created_utc")
        published = datetime.fromtimestamp(created, tz=timezone.utc).isoformat() if created else now_utc()
        score    = p.get("score", 0)

        items.append({
            "title":       title,
            "description": selftext or f"Reddit discussion (score: {score})",
            "url":         url,
            "cve_id":      extract_cve_id(title),
            "source":      "Reddit/netsec",
            "category":    infer_category(title, "news"),
            "severity":    infer_severity(title, "low"),
            "cvss_score":  None,
            "published":   published,
        })

    log.info(f"  Got {len(items)} posts from Reddit r/netsec")
    return items


def fetch_otx_pulse(api_key: str) -> list[dict]:
    if not api_key:
        log.info("OTX_API_KEY not set — skipping AlienVault OTX")
        return []

    log.info("Fetching AlienVault OTX pulses...")
    items = []
    hdrs  = {**HEADERS, "X-OTX-API-KEY": api_key}
    data  = make_request(
        "https://otx.alienvault.com/api/v1/pulses/subscribed",
        headers=hdrs,
        params={"limit": MAX_ITEMS_PER_SOURCE}
    )
    if not data:
        log.warning("OTX API returned no data")
        return items

    for pulse in data.get("results", []):
        name        = pulse.get("name", "Untitled")
        description = (pulse.get("description") or "")[:400]
        pulse_id    = pulse.get("id", "")

        items.append({
            "title":       name,
            "description": description,
            "url":         f"https://otx.alienvault.com/pulse/{pulse_id}",
            "cve_id":      None,
            "source":      "AlienVault OTX",
            "category":    "incident",
            "severity":    infer_severity(name + " " + description, "medium"),
            "cvss_score":  None,
            "published":   parse_date(pulse.get("created", now_utc())),
        })

    log.info(f"  Got {len(items)} pulses from AlienVault OTX")
    return items


# ─── Intel Inference Helpers ─────────────────────────────────────────────────

def cvss_to_severity(score: float | None) -> str:
    if score is None: return "medium"
    if score >= 9.0:  return "critical"
    if score >= 7.0:  return "high"
    if score >= 4.0:  return "medium"
    return "low"

def infer_severity(text: str, default: str = "medium") -> str:
    t = text.lower()
    if any(kw in t for kw in ["critical","zero-day","0-day","actively exploited","rce","remote code execution","unauthenticated","wormable"]):
        return "critical"
    if any(kw in t for kw in ["high","privilege escalation","authentication bypass","ransomware","data breach","nation-state","apt"]):
        return "high"
    if any(kw in t for kw in ["medium","xss","csrf","injection","phishing","malware"]):
        return "medium"
    if any(kw in t for kw in ["low","informational","advisory","guide","best practice"]):
        return "low"
    return default

def infer_category(text: str, default: str = "news") -> str:
    t = text.lower()
    if any(kw in t for kw in ["cve-","vulnerability","patch","exploit","nvd"]):
        return "cve"
    if any(kw in t for kw in ["breach","attack","ransomware","hack","intrusion","stolen","compromised","leaked","incident"]):
        return "incident"
    if any(kw in t for kw in ["advisory","alert","directive","guidance","warning","cisa","recommendation","patch tuesday"]):
        return "advisory"
    return default

def extract_cve_id(text: str) -> str | None:
    match = re.search(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
    return match.group(0).upper() if match else None

def deduplicate(items: list[dict]) -> list[dict]:
    seen, unique = set(), []
    for item in items:
        key = item["title"].lower().strip()[:80]
        if key not in seen:
            seen.add(key)
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
            all_items.extend(fetch_rss(source))
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

    # 4. AlienVault OTX
    try:
        all_items.extend(fetch_otx_pulse(OTX_API_KEY))
    except Exception as e:
        log.error(f"OTX fetch failed: {e}")

    # Deduplicate
    all_items = deduplicate(all_items)

    # ── Map MITRE ATT&CK TTPs ─────────────────────────────────────────────────
    log.info("Mapping MITRE ATT&CK TTPs...")
    for item in all_items:
        text         = item.get("title", "") + " " + item.get("description", "")
        item["ttps"] = map_ttps(text)
    ttp_total = sum(len(i["ttps"]) for i in all_items)
    log.info(f"  Mapped {ttp_total} TTP associations across {len(all_items)} items")

    # Sort by published date descending (newest first)
    all_items.sort(key=lambda x: x.get("published", ""), reverse=True)

    # ── Gemini AI Enrichment ──────────────────────────────────────────────────
    # Enriches top GEMINI_ENRICH_TOP_N items with ai_summary, workflow_graph,
    # and severity_score. All other items get null values for these fields.
    enrich_with_gemini(all_items, GEMINI_API_KEY)

    # Build final output
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
