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
  - AI Enrichment             → Groq (primary) with Gemini fallback

AI enrichment adds per-item:
  - ai_summary      : 2-3 sentence BLUF threat analysis
  - severity_score  : float 0.0–10.0
  - workflow_graph  : Mermaid LR attack-flow diagram with TTP IDs on edges
  - ai_provider     : "groq" | "gemini" | "none"
  - ai_model        : model name used

Output: data/intel.json  +  data/archive/YYYY-MM-DD.json

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

# ── MITRE ATT&CK full database ────────────────────────────────────────────────
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

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("cyberwatch")

# ── Configuration ─────────────────────────────────────────────────────────────
OUTPUT_PATH          = Path("data/intel.json")
ARCHIVE_DIR          = Path("data/archive")
MAX_ITEMS_PER_SOURCE = 10
NVD_LOOKBACK_DAYS    = 10
REQUEST_TIMEOUT      = 30
AI_ENRICH_LIMIT      = 15

# API keys (set as GitHub Actions Secrets)
OTX_API_KEY    = os.environ.get("OTX_API_KEY", "")
GROQ_API_KEY   = os.environ.get("GROQ_API_KEY", "")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")

# Groq models — primary is the high-quality 70B, fallback is ultra-fast 8B
GROQ_MODEL_PRIMARY  = "llama-3.3-70b-versatile"
GROQ_MODEL_FALLBACK = "llama-3.1-8b-instant"
GEMINI_MODEL        = "gemini-2.5-flash-lite"

# Sleep between Groq calls (respects 30 RPM free tier)
GROQ_SLEEP_SECS   = 3
GEMINI_SLEEP_SECS = 6

HEADERS = {"User-Agent": "CyberWatch/1.0 (GitHub personal project)"}

# Default graph used when ALL AI providers fail
DEFAULT_WORKFLOW_GRAPH = (
    "graph LR\n"
    "    A([Threat Actor]):::actor -->|Recon| B[Initial Access]:::tactic\n"
    "    B -->|Exploit| C[Execution]:::tactic\n"
    "    C -->|Persist| D[Impact]:::tactic\n"
    "    classDef actor fill:#1a0e2e,stroke:#a78bfa,color:#c9d8e8\n"
    "    classDef tactic fill:#0d2038,stroke:#4da6ff,color:#c9d8e8"
)

# ── RSS Feed Sources ──────────────────────────────────────────────────────────
RSS_SOURCES = [
    {"name": "CISA",             "url": "https://www.cisa.gov/news.xml",                   "category": "advisory", "severity": "high"},
    {"name": "The Hacker News",  "url": "https://feeds.feedburner.com/TheHackersNews",      "category": "news",     "severity": "medium"},
    {"name": "Bleeping Computer","url": "https://www.bleepingcomputer.com/feed/",           "category": "news",     "severity": "medium"},
    {"name": "Krebs on Security","url": "https://krebsonsecurity.com/feed/",                "category": "news",     "severity": "medium"},
    {"name": "SANS ISC",         "url": "https://isc.sans.edu/rssfeed_full.xml",            "category": "news",     "severity": "low"},
    {"name": "TheRecord Media",  "url": "https://therecord.media/feed",                     "category": "news",     "severity": "high"},
    {"name": "Dark Reading",     "url": "https://www.darkreading.com/rss.xml",              "category": "news",     "severity": "medium"},
    {"name": "SecurityWeek",     "url": "https://www.securityweek.com/feed/",               "category": "news",     "severity": "medium"},
    {"name": "Threatpost",       "url": "https://threatpost.com/feed/",                     "category": "news",     "severity": "medium"},
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_date(date_str) -> str:
    if not date_str:
        return now_utc()
    try:
        if hasattr(date_str, 'tm_year'):
            return datetime(*date_str[:6], tzinfo=timezone.utc).isoformat()
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
        resp = requests.get(
            url, headers=headers or HEADERS, params=params, timeout=REQUEST_TIMEOUT
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
        log.warning(f"Invalid JSON: {url}")
    return None


def ai_score_to_severity(score: float) -> str:
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 4.0: return "medium"
    return "low"


# ── AI Prompt Builder ─────────────────────────────────────────────────────────

def build_prompt(item: dict) -> str:
    """
    Build a prompt that asks the AI to produce:
      - ai_summary: 2-3 sentence BLUF
      - severity_score: float 0-10
      - workflow_graph: Mermaid LR diagram with TTP IDs on edge labels

    The graph format uses ATT&CK tactic phases as rectangular nodes and puts
    specific TTP IDs (e.g. |T1566.001|) as edge labels so the JS UI can
    parse them and build interactive TTP detail cards beneath the diagram.
    """
    ttp_str = ", ".join(
        f"{t['id']} ({t['name']})" for t in item.get("ttps", [])[:6]
    ) or "None detected"

    return f"""You are a senior threat intelligence analyst. Analyze this cybersecurity item and respond with ONLY a valid JSON object — no markdown, no code fences, no preamble.

Return exactly this structure:
{{
  "ai_summary": "2-3 sentences: what the threat is technically, its real-world impact, and the single most important defender action.",
  "severity_score": 7.5,
  "workflow_graph": "graph LR\\n    A([Threat Actor]):::actor -->|T1566| B[Initial Access]:::tactic\\n    B -->|T1059.001| C[Execution]:::tactic\\n    C -->|T1041| D[Command and Control]:::tactic\\n    D -->|T1486| E[Impact]:::tactic\\n    classDef actor fill:#1a0e2e,stroke:#a78bfa,color:#c9d8e8\\n    classDef tactic fill:#0d2038,stroke:#4da6ff,color:#c9d8e8"
}}

RULES:
- ai_summary: 2-3 sentences max. Technical. Actionable. No fluff.
- severity_score: 0.0 to 10.0 float. Base on actual impact:
    9-10 = critical/RCE/0-day/wormable
    7-8  = high/privilege escalation/data breach/ransomware
    4-6  = medium/limited scope
    1-3  = low/informational
- workflow_graph: valid Mermaid "graph LR" string with \\n for newlines:
    * Use 4-6 nodes only. Node labels = ATT&CK tactic phase names.
    * IMPORTANT: edge labels must be REAL TTP IDs from the item (e.g. |T1566|, |T1059.001|)
    * First node must be A([Threat Actor]):::actor
    * All other nodes use :::tactic class
    * End with the two classDef lines exactly as shown above
    * Escape quotes: use single quotes inside node labels if needed

THREAT ITEM:
Title: {item.get('title', '')[:200]}
Description: {item.get('description', '')[:500]}
Category: {item.get('category', '')}
TTPs Detected: {ttp_str}
CVE ID: {item.get('cve_id') or 'N/A'}
CVSS Score: {item.get('cvss_score') or 'N/A'}"""


# ── AI Response Parser ────────────────────────────────────────────────────────

def parse_ai_response(raw: str) -> dict:
    """
    Robustly extract and parse JSON from AI response.
    Handles markdown code fences, leading/trailing text, etc.
    """
    raw = raw.strip()
    # Strip markdown code fences
    raw = re.sub(r"^```(?:json)?\s*\n?", "", raw, flags=re.MULTILINE)
    raw = re.sub(r"\n?```\s*$",           "", raw, flags=re.MULTILINE)
    raw = raw.strip()
    # Extract just the outermost JSON object
    json_match = re.search(r'\{.*\}', raw, re.DOTALL)
    if json_match:
        raw = json_match.group(0)
    return json.loads(raw)


def postprocess_graph(raw_graph: str) -> str:
    """
    Clean up the AI-generated Mermaid graph:
    - Normalize \\n to real newlines
    - Ensure it starts with 'graph LR'
    - Remove any existing classDef lines, then append ours
    - Strip illegal characters that break Mermaid parsing
    """
    if not raw_graph or not raw_graph.strip():
        return DEFAULT_WORKFLOW_GRAPH

    # Unescape literal \n sequences the AI may have written
    graph = raw_graph.replace("\\n", "\n").strip()

    # Ensure it starts with a valid graph directive
    if not re.match(r'^graph\s+(LR|TD|TB|RL|BT)', graph, re.IGNORECASE):
        graph = "graph LR\n" + graph

    # Keep only lines that are not classDef (we append our own)
    lines = [l for l in graph.split("\n") if not l.strip().startswith("classDef")]
    graph = "\n".join(lines).rstrip()

    # Append standardised dark-terminal styling
    graph += (
        "\n    classDef actor fill:#1a0e2e,stroke:#a78bfa,color:#c9d8e8,font-weight:bold"
        "\n    classDef tactic fill:#0d2038,stroke:#4da6ff,color:#c9d8e8"
    )

    return graph


# ── Groq API Caller ───────────────────────────────────────────────────────────

def call_groq(prompt: str) -> tuple[str | None, str | None]:
    """
    Call Groq's OpenAI-compatible API directly via requests.
    Tries llama-3.3-70b-versatile first, falls back to llama-3.1-8b-instant.
    Returns (raw_text, model_used) or (None, None) on failure.
    """
    if not GROQ_API_KEY:
        return None, None

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json",
    }

    for model in [GROQ_MODEL_PRIMARY, GROQ_MODEL_FALLBACK]:
        try:
            body = {
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "max_tokens": 700,
                "response_format": {"type": "json_object"},
            }
            resp = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers=headers,
                json=body,
                timeout=REQUEST_TIMEOUT,
            )

            # 429 = rate limited on this model → try next
            if resp.status_code == 429:
                log.warning(f"Groq rate limit on {model}, trying fallback...")
                time.sleep(5)
                continue

            resp.raise_for_status()
            data = resp.json()
            raw  = data["choices"][0]["message"]["content"]
            return raw, model

        except requests.exceptions.Timeout:
            log.warning(f"Groq timeout ({model})")
        except requests.exceptions.RequestException as e:
            log.warning(f"Groq request error ({model}): {e}")
        except (KeyError, IndexError, json.JSONDecodeError) as e:
            log.warning(f"Groq response parse error ({model}): {e}")

    return None, None


# ── Gemini API Caller ─────────────────────────────────────────────────────────

def call_gemini(prompt: str) -> tuple[str | None, str | None]:
    """
    Call Gemini via the google-generativeai SDK.
    Returns (raw_text, model_name) or (None, None) on failure.
    """
    if not GEMINI_API_KEY:
        return None, None

    try:
        import google.generativeai as genai
        genai.configure(api_key=GEMINI_API_KEY)
        model    = genai.GenerativeModel(GEMINI_MODEL)
        response = model.generate_content(prompt)
        return response.text.strip(), GEMINI_MODEL
    except ImportError:
        log.warning("google-generativeai not installed — Gemini unavailable")
        return None, None
    except Exception as e:
        log.warning(f"Gemini call failed: {e}")
        return None, None


# ── Main AI Enrichment Pipeline ───────────────────────────────────────────────

def apply_parsed(item: dict, parsed: dict, provider: str, model: str) -> None:
    """Write parsed AI fields into an item dict."""
    item["ai_summary"] = str(parsed.get("ai_summary", "")).strip() or "AI analysis pending"

    raw_graph = str(parsed.get("workflow_graph", "")).strip()
    item["workflow_graph"] = postprocess_graph(raw_graph)

    raw_score = parsed.get("severity_score", None)
    try:
        score = float(raw_score)
        score = max(0.0, min(10.0, score))
    except (TypeError, ValueError):
        score = 5.0
    item["severity_score"] = round(score, 1)
    item["severity"]       = ai_score_to_severity(score)
    item["ai_provider"]    = provider
    item["ai_model"]       = model


def set_fallback(item: dict) -> None:
    """Set safe fallback values when all AI providers fail."""
    item.setdefault("ai_summary",     "AI analysis pending")
    item.setdefault("workflow_graph", DEFAULT_WORKFLOW_GRAPH)
    item.setdefault("severity_score", None)
    item.setdefault("ai_provider",    "none")
    item.setdefault("ai_model",       "none")


def enrich_with_ai(items: list[dict]) -> list[dict]:
    """
    Enrich the top AI_ENRICH_LIMIT items with AI analysis.

    Provider priority:
      1. Groq  (llama-3.3-70b-versatile → llama-3.1-8b-instant)
      2. Gemini (gemini-2.5-flash-lite) as fallback if Groq fails
      3. Safe defaults if both fail

    The sleep strategy:
      - Between Groq calls: GROQ_SLEEP_SECS (3s) — respects 30 RPM
      - Extra sleep before Gemini fallback: GEMINI_SLEEP_SECS (6s) — 10 RPM
    """
    if not GROQ_API_KEY and not GEMINI_API_KEY:
        log.info("No AI keys set — skipping enrichment")
        for item in items:
            set_fallback(item)
        return items

    groq_available   = bool(GROQ_API_KEY)
    gemini_available = bool(GEMINI_API_KEY)

    log.info(
        f"AI enrichment — providers: "
        f"{'Groq ✓' if groq_available else 'Groq ✗'}  "
        f"{'Gemini ✓' if gemini_available else 'Gemini ✗'}"
    )
    log.info(f"Enriching top {min(AI_ENRICH_LIMIT, len(items))} items...")

    for i, item in enumerate(items[:AI_ENRICH_LIMIT]):
        prompt = build_prompt(item)
        enriched = False

        # ── Attempt 1: Groq ──────────────────────────────────────────────────
        if groq_available:
            raw, model = call_groq(prompt)
            if raw:
                try:
                    parsed = parse_ai_response(raw)
                    apply_parsed(item, parsed, "groq", model)
                    log.info(
                        f"  ✓ Groq [{i+1:02d}/{min(AI_ENRICH_LIMIT,len(items))}]"
                        f" score={item['severity_score']} sev={item['severity']}"
                        f" | {item['title'][:55]}"
                    )
                    enriched = True
                except (json.JSONDecodeError, KeyError, ValueError) as e:
                    log.warning(f"  ✗ Groq JSON parse error: {e}")

        # ── Attempt 2: Gemini fallback ───────────────────────────────────────
        if not enriched and gemini_available:
            log.info(f"  ↳ Falling back to Gemini for item {i+1}...")
            time.sleep(GEMINI_SLEEP_SECS)
            raw, model = call_gemini(prompt)
            if raw:
                try:
                    parsed = parse_ai_response(raw)
                    apply_parsed(item, parsed, "gemini", model)
                    log.info(
                        f"  ✓ Gemini [{i+1:02d}/{min(AI_ENRICH_LIMIT,len(items))}]"
                        f" score={item['severity_score']} sev={item['severity']}"
                        f" | {item['title'][:55]}"
                    )
                    enriched = True
                except (json.JSONDecodeError, KeyError, ValueError) as e:
                    log.warning(f"  ✗ Gemini JSON parse error: {e}")

        # ── Both failed ──────────────────────────────────────────────────────
        if not enriched:
            log.warning(f"  ✗ Both providers failed for item {i+1} — using fallback")
            set_fallback(item)

        # Rate-limit sleep between items (skip after last one)
        if i < min(AI_ENRICH_LIMIT, len(items)) - 1:
            time.sleep(GROQ_SLEEP_SECS)

    # Fill defaults for items beyond the enrichment limit
    for item in items[AI_ENRICH_LIMIT:]:
        set_fallback(item)

    enriched_count = sum(
        1 for item in items[:AI_ENRICH_LIMIT]
        if item.get("ai_summary", "") not in ("", "AI analysis pending")
    )
    log.info(
        f"AI enrichment complete — "
        f"{enriched_count}/{min(AI_ENRICH_LIMIT, len(items))} items enriched"
    )
    return items


# ── Fetchers ──────────────────────────────────────────────────────────────────

def fetch_rss(source: dict) -> list[dict]:
    log.info(f"Fetching RSS: {source['name']} ({source['url']})")
    items = []
    try:
        feed = feedparser.parse(source["url"])
        if feed.bozo and not feed.entries:
            log.warning(f"Feed error {source['name']}: {feed.bozo_exception}")
            return items
        for entry in feed.entries[:MAX_ITEMS_PER_SOURCE]:
            title       = entry.get("title", "Untitled")
            link        = entry.get("link", "")
            description = ""
            if hasattr(entry, "summary"):
                description = clean_html(entry.summary)
            elif hasattr(entry, "content"):
                description = clean_html(entry.content[0].get("value", ""))
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
        log.error(f"Unexpected error {source['name']}: {e}")
    log.info(f"  Got {len(items)} items from {source['name']}")
    return items


def fetch_nvd_cves() -> list[dict]:
    log.info("Fetching CVEs from NVD API...")
    items = []
    end_date   = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=NVD_LOOKBACK_DAYS)
    params = {
        "pubStartDate":   start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate":     end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": MAX_ITEMS_PER_SOURCE,
    }
    data = make_request("https://services.nvd.nist.gov/rest/json/cves/2.0", params=params)
    if not data:
        log.warning("NVD API returned no data")
        return items
    for vuln in data.get("vulnerabilities", []):
        cve         = vuln.get("cve", {})
        cve_id      = cve.get("id", "")
        descriptions = cve.get("descriptions", [])
        description  = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available."
        )[:400]
        cvss_score = None
        severity   = "medium"
        for mk in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            ml = cve.get("metrics", {}).get(mk, [])
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
    headers = {**HEADERS, "User-Agent": "CyberWatch/1.0 (personal dashboard)"}
    data = make_request("https://www.reddit.com/r/netsec.json?limit=15", headers=headers)
    if not data:
        log.warning("Reddit r/netsec returned no data")
        return items
    for post in data.get("data", {}).get("children", []):
        p = post.get("data", {})
        if p.get("stickied"):
            continue
        title     = p.get("title", "Untitled")
        created   = p.get("created_utc")
        published = (
            datetime.fromtimestamp(created, tz=timezone.utc).isoformat()
            if created else now_utc()
        )
        items.append({
            "title":       title,
            "description": clean_html(p.get("selftext", "")) or f"Reddit (score: {p.get('score',0)})",
            "url":         p.get("url", ""),
            "cve_id":      extract_cve_id(title),
            "source":      "Reddit/netsec",
            "category":    infer_category(title, "news"),
            "severity":    infer_severity(title, "low"),
            "cvss_score":  None,
            "published":   published,
        })
    log.info(f"  Got {len(items)} posts from Reddit r/netsec")
    return items


def fetch_epss_scores(cve_ids: list[str]) -> dict[str, float]:
    """Fetch EPSS scores from FIRST.org for given CVE IDs."""
    if not cve_ids:
        return {}
    log.info(f"Fetching EPSS scores for {len(cve_ids)} CVEs...")
    try:
        resp = requests.post(
            "https://api.first.org/epss/v1/epss",
            data={"cve": cve_ids},
            headers={**HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
            timeout=REQUEST_TIMEOUT
        )
        resp.raise_for_status()
        data = resp.json()
        scores = {}
        for entry in data.get("data", []):
            cve = entry.get("cve", "")
            epss = entry.get("epss")
            if cve and epss is not None:
                scores[cve.upper()] = float(epss)
        log.info(f"  Got EPSS scores for {len(scores)} CVEs")
        return scores
    except Exception as e:
        log.warning(f"EPSS fetch failed: {e}")
        return {}


def fetch_cisa_kev() -> set[str]:
    """Fetch CISA Known Exploited Vulnerabilities catalog."""
    log.info("Fetching CISA KEV catalog...")
    try:
        resp = requests.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            timeout=REQUEST_TIMEOUT
        )
        resp.raise_for_status()
        data = resp.json()
        cve_ids = set()
        for vuln in data.get("vulnerabilities", []):
            cve_id = vuln.get("cveID", "")
            if cve_id:
                cve_ids.add(cve_id.upper())
        log.info(f"  Got {len(cve_ids)} CVEs in CISA KEV")
        return cve_ids
    except Exception as e:
        log.warning(f"CISA KEV fetch failed: {e}")
        return {}


# Threat actor detection
THREAT_ACTORS = {
    "Lazarus": ["lazarus", "hidden cobra", "zinc", "guardians of peace", "labyrinth chollima"],
    "APT29": ["apt29", "cozy bear", "the duke", "cozy duke", "yttrium"],
    "APT28": ["apt28", "fancy bear", "sednit", "pawn storm", "strontium"],
    "APT41": ["apt41", "barium", "winnti", "wicked panda", "lead"],
    "APT1": ["apt1", "comment crew", "comment groupe", "shanghai group"],
    "APT17": ["apt17", "tailgator team", "austin group"],
    "APT32": ["apt32", "oceanlotus", "fin6", "gold dragon"],
    "APT33": ["apt33", "elfin", "refined kit", "shamoon"],
    "APT34": ["apt34", "oilrig", "helix kit", "parsimonious"],
    "APT38": ["apt38", "lazarus", "hidden cobra", "zinc"],
    "FIN7": ["fin7", "carbanak", "navigator"],
    "FIN4": ["fin4", "promethium"],
    "Cozy Bear": ["cozy bear", "apt29"],
    "DarkSide": ["darkside", "blackmatter"],
    "REvil": ["revil", "sodinokibi"],
    "LockBit": ["lockbit"],
    "BlackCat": ["blackcat", "alphv"],
    "Clop": ["clop", "cl0p"],
    "Conti": ["conti", "wizard spider"],
    "TrickBot": ["trickbot", "trickster"],
    "Emotet": ["emotet", "heodo"],
    "Tauri": ["tauri", "mint sandstorm"],
    "Moses Staff": ["moses staff"],
    "MSTIC": ["mstic", "microsoft threat intelligence"],
    "Sandworm": ["sandworm", "voodoo bear", "electrum"],
    "Carbanak": ["carbanak", "fin7"],
    "Nobelium": ["nobelium", "solarwinds"],
    "Kaseya": ["kaseya"],
    "Log4j": ["log4shell", "log4j"],
    "FunkSec": ["funksec"],
    "MirrorFace": ["mirrorface"],
    "Salt Typhoon": ["salt typhoon"],
    "EAGERBEE": ["eagerbee"],
}

def detect_threat_actors(text: str) -> list[str]:
    """Detect threat actors mentioned in text."""
    text_lower = text.lower()
    actors = []
    for actor, keywords in THREAT_ACTORS.items():
        for kw in keywords:
            if kw in text_lower:
                actors.append(actor)
                break
    return list(set(actors))


def fetch_otx_pulse(api_key: str) -> list[dict]:
    if not api_key:
        log.info("OTX_API_KEY not set — skipping AlienVault OTX")
        return []
    log.info("Fetching AlienVault OTX pulses...")
    items = []
    headers = {**HEADERS, "X-OTX-API-KEY": api_key}
    data = make_request(
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
        items.append({
            "title":       name,
            "description": description,
            "url":         f"https://otx.alienvault.com/pulse/{pulse.get('id','')}",
            "cve_id":      None,
            "source":      "AlienVault OTX",
            "category":    "incident",
            "severity":    infer_severity(name + " " + description, "medium"),
            "cvss_score":  None,
            "published":   parse_date(pulse.get("created", now_utc())),
        })
    log.info(f"  Got {len(items)} pulses from AlienVault OTX")
    return items


# ── Intel Inference Helpers ───────────────────────────────────────────────────

def cvss_to_severity(score) -> str:
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


# ── Main ─────────────────────────────────────────────────────────────────────

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
            log.error(f"Failed {source['name']}: {e}")
        time.sleep(1)

    # 2. NVD CVE API
    try:
        all_items.extend(fetch_nvd_cves())
    except Exception as e:
        log.error(f"NVD fetch failed: {e}")
    time.sleep(1)

    # 3. Reddit
    try:
        all_items.extend(fetch_reddit_netsec())
    except Exception as e:
        log.error(f"Reddit fetch failed: {e}")

    # 4. OTX
    try:
        all_items.extend(fetch_otx_pulse(OTX_API_KEY))
    except Exception as e:
        log.error(f"OTX fetch failed: {e}")

    # Deduplicate + sort newest first
    all_items = deduplicate(all_items)
    all_items.sort(key=lambda x: x.get("published", ""), reverse=True)

    # 5. Map MITRE ATT&CK TTPs
    log.info("Mapping MITRE ATT&CK TTPs...")
    for item in all_items:
        item["ttps"] = map_ttps(item.get("title","") + " " + item.get("description",""))
    ttp_total = sum(len(i["ttps"]) for i in all_items)
    log.info(f"  Mapped {ttp_total} TTP associations across {len(all_items)} items")

    # 6. Fetch EPSS scores for CVEs
    cve_ids = [item["cve_id"] for item in all_items if item.get("cve_id")]
    if cve_ids:
        epss_scores = fetch_epss_scores(cve_ids)
        for item in all_items:
            if item.get("cve_id"):
                item["epss_score"] = epss_scores.get(item["cve_id"].upper())
        log.info(f"  Applied EPSS scores to {len([i for i in all_items if i.get('epss_score')])} items")

    # 7. Fetch CISA KEV and mark known exploited CVEs
    cisa_kev = fetch_cisa_kev()
    if cisa_kev:
        kev_count = 0
        for item in all_items:
            if item.get("cve_id") and item["cve_id"].upper() in cisa_kev:
                item["cisa_kev"] = True
                kev_count += 1
        log.info(f"  Marked {kev_count} CVEs from CISA KEV catalog")

    # 8. Detect threat actors
    log.info("Detecting threat actors...")
    actor_count = 0
    for item in all_items:
        text = item.get("title", "") + " " + item.get("description", "")
        actors = detect_threat_actors(text)
        if actors:
            item["threat_actors"] = actors
            actor_count += 1
    log.info(f"  Detected threat actors in {actor_count} items")

    # 9. AI Enrichment (Groq primary → Gemini fallback)
    try:
        all_items = enrich_with_ai(all_items)
    except Exception as e:
        log.error(f"AI enrichment pipeline failed: {e}")
        for item in all_items:
            set_fallback(item)

    # 7. Write outputs
    output = {
        "last_updated": now_utc(),
        "total_items":  len(all_items),
        "items":        all_items,
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    log.info(f"✓ Wrote {len(all_items)} items to {OUTPUT_PATH}")

    today_str    = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    archive_path = ARCHIVE_DIR / f"{today_str}.json"
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    with open(archive_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    log.info(f"✓ Archived to {archive_path}")

    log.info("═" * 60)
    log.info(f"CYBERWATCH — Complete. {len(all_items)} items ready.")
    log.info("═" * 60)


if __name__ == "__main__":
    main()