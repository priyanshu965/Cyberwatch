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
  - Reddit r/netsec JSON      → Community intel
  - AlienVault OTX API        → Threat pulse (if API key set)

Output: data/intel.json

Run manually:
  pip install requests feedparser
  python scripts/fetch_intel.py

Run via GitHub Actions: automatically on schedule (see update.yml)
"""

import json
import os
import sys
import time
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests
import feedparser

# MITRE ATT&CK full database (246 techniques + 445 sub-techniques)
# Imported from the companion module in the same directory
try:
    from mitre_ttps import MITRE_TECHNIQUES, TACTIC_ORDER, map_ttps
except ImportError:
    # Fallback if run from a different working directory
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

# Output path (relative to repo root)
OUTPUT_PATH = Path("data/intel.json")

# How many items to keep per source (to keep JSON file manageable)
MAX_ITEMS_PER_SOURCE = 10

# NVD API: fetch CVEs published in the last N days
NVD_LOOKBACK_DAYS = 10

# Request timeout in seconds
REQUEST_TIMEOUT = 30

# Optional: Set these as GitHub Actions Secrets in your repo
# Settings → Secrets and variables → Actions → New repository secret
OTX_API_KEY = os.environ.get("OTX_API_KEY", "")

# User-Agent header (be polite to RSS servers)
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
    """Return current UTC time as ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


def parse_date(date_str: str) -> str:
    """
    Try to parse a date string into ISO 8601 format.
    Falls back to current time if parsing fails.
    """
    if not date_str:
        return now_utc()
    try:
        # feedparser returns a time.struct_time
        if hasattr(date_str, 'tm_year'):
            dt = datetime(*date_str[:6], tzinfo=timezone.utc)
            return dt.isoformat()
        # Try common ISO formats
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
    """Rudimentary HTML tag stripper for RSS descriptions."""
    if not text:
        return ""
    import re
    text = re.sub(r"<[^>]+>", "", text)           # Remove HTML tags
    text = re.sub(r"\s+", " ", text).strip()       # Collapse whitespace
    return text[:999]                               # Truncate to 999 chars


def make_request(url: str, headers: dict = None, params: dict = None) -> dict | None:
    """
    Make an HTTP GET request with error handling.
    Returns the JSON response dict or None on failure.
    """
    try:
        resp = requests.get(
            url,
            headers=headers or HEADERS,
            params=params,
            timeout=REQUEST_TIMEOUT
        )
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


# ─── Fetchers ────────────────────────────────────────────────────────────────

def fetch_rss(source: dict) -> list[dict]:
    """
    Fetch and parse an RSS/Atom feed.
    Returns a list of intel item dicts.
    """
    log.info(f"Fetching RSS: {source['name']} ({source['url']})")
    items = []

    try:
        # feedparser handles fetching and parsing in one call
        feed = feedparser.parse(source["url"])

        if feed.bozo and not feed.entries:
            log.warning(f"Feed parse error for {source['name']}: {feed.bozo_exception}")
            return items

        for entry in feed.entries[:MAX_ITEMS_PER_SOURCE]:
            title = entry.get("title", "Untitled")
            link  = entry.get("link", "")

            # Description: try summary, then content
            description = ""
            if hasattr(entry, "summary"):
                description += clean_html(entry.summary)
            elif hasattr(entry, "content"):
                description += " " + clean_html(entry.content[0].get("value", ""))
            description = description.strip()[:999]

            # Published date
            pub_date = parse_date(entry.get("published_parsed") or entry.get("updated_parsed"))

            # Guess severity from title/description keywords
            severity = infer_severity(title + " " + description, source["severity"])

            # Guess category from title keywords
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
    """
    Fetch recent CVEs from the NIST NVD API (free, no key needed).
    API docs: https://nvd.nist.gov/developers/vulnerabilities
    """
    log.info("Fetching CVEs from NVD API...")
    items = []

    # Calculate date range: last N days
    end_date   = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=NVD_LOOKBACK_DAYS)

    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate":   end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": MAX_ITEMS_PER_SOURCE,
    }

    data = make_request(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params=params
    )

    if not data:
        log.warning("NVD API returned no data")
        return items

    vulnerabilities = data.get("vulnerabilities", [])

    for vuln in vulnerabilities:
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")

        # Get English description
        descriptions = cve.get("descriptions", [])
        description  = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available."
        )[:400]

        # Get CVSS score (try v3.1 first, then v3.0, then v2)
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

        # Published date
        published = parse_date(cve.get("published", ""))

        items.append({
            "title":       f"{cve_id}: {description[:80]}...",
            "description": description,
            "url":         f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "cve_id":      cve_id,
            "source":      "NVD",
            "category":    "cve",
            "severity":    severity,
            "cvss_score":  cvss_score,
            "published":   published,
        })

    log.info(f"  Got {len(items)} CVEs from NVD")
    return items


def fetch_reddit_netsec() -> list[dict]:
    """
    Fetch top posts from r/netsec using Reddit's public JSON endpoint.
    No API key required.
    """
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

        # Skip stickied mod posts
        if p.get("stickied"):
            continue

        title     = p.get("title", "Untitled")
        url       = p.get("url", "")
        selftext  = clean_html(p.get("selftext", ""))
        created   = p.get("created_utc")
        published = datetime.fromtimestamp(created, tz=timezone.utc).isoformat() if created else now_utc()
        score     = p.get("score", 0)

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
    """
    Fetch recent threat pulses from AlienVault OTX (free account needed).
    Sign up at: https://otx.alienvault.com
    Set OTX_API_KEY as a GitHub Actions Secret.
    """
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
        tags        = pulse.get("tags", [])
        created     = pulse.get("created", now_utc())
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
            "published":   parse_date(created),
        })

    log.info(f"  Got {len(items)} pulses from AlienVault OTX")
    return items


# ─── Intel Inference Helpers ─────────────────────────────────────────────────

def cvss_to_severity(score: float | None) -> str:
    """Convert a CVSS numeric score to a severity label."""
    if score is None:
        return "medium"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def infer_severity(text: str, default: str = "medium") -> str:
    """
    Guess severity from keywords in the text.
    Used for RSS items that don't have a numeric CVSS score.
    """
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
    """
    Guess the item category from keywords.
    Categories: cve, advisory, incident, news
    """
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
    """
    Extract the first CVE ID found in text (e.g. CVE-2024-12345).
    Returns None if not found.
    """
    import re
    match = re.search(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
    return match.group(0).upper() if match else None



def deduplicate(items: list[dict]) -> list[dict]:
    """
    Remove duplicate items by title similarity.
    Keeps the first occurrence (usually most authoritative source).
    """
    seen_titles = set()
    unique      = []

    for item in items:
        # Normalize title for comparison
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
        time.sleep(1)  # Be polite between requests

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

    # 4. AlienVault OTX (only if API key is set)
    try:
        all_items.extend(fetch_otx_pulse(OTX_API_KEY))
    except Exception as e:
        log.error(f"OTX fetch failed: {e}")

    # Deduplicate
    all_items = deduplicate(all_items)

    # ── Map MITRE ATT&CK TTPs ─────────────────────────────────────────────────
    # Runs keyword matching on every item's title + description.
    # Adds a "ttps" list of matched technique dicts to each item.
    log.info("Mapping MITRE ATT&CK TTPs...")
    for item in all_items:
        text = (item.get("title", "") + " " + item.get("description", ""))
        item["ttps"] = map_ttps(text)

    ttp_total = sum(len(i["ttps"]) for i in all_items)
    log.info(f"  Mapped {ttp_total} TTP associations across {len(all_items)} items")

    # Sort by published date descending
    all_items.sort(
        key=lambda x: x.get("published", ""),
        reverse=True
    )

    # Build final output
    output = {
        "last_updated": now_utc(),
        "total_items":  len(all_items),
        "items":        all_items,
    }

    # Ensure the data/ directory exists
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    # Write JSON
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    log.info("═" * 60)
    log.info(f"✓ Wrote {len(all_items)} items to {OUTPUT_PATH}")
    log.info("═" * 60)


if __name__ == "__main__":
    main()
