import os
import json
import requests
import feedparser
import logging
from datetime import datetime, timezone
from pathlib import Path
from mitre_ttps import map_ttps

# Config
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("CyberWatch")

def get_ai_enrichment(title, description):
    """Calls Gemini to get a 2-sentence summary and a Mermaid flowchart."""
    if not GEMINI_API_KEY:
        return "Summary unavailable.", "graph TD\n    A[Incident] --> B[Details restricted]"
    
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={GEMINI_API_KEY}"
    prompt = f"""
    Analyze this cyber threat:
    Title: {title}
    Description: {description}
    
    Provide a JSON response with:
    1. "summary": A 2-sentence technical summary.
    2. "mermaid": A Mermaid.js 'graph TD' flowchart showing the attack stages.
    3. "severity_score": A float 0.0-10.0 based on impact.
    """
    
    try:
        response = requests.post(url, json={"contents": [{"parts":[{"text": prompt}]}]}, timeout=10)
        raw_text = response.json()['candidates'][0]['content']['parts'][0]['text']
        # Clean the markdown if LLM returns it
        data = json.loads(raw_text.replace("```json", "").replace("```", ""))
        return data.get("summary"), data.get("mermaid"), data.get("severity_score", 5.0)
    except Exception as e:
        log.error(f"AI Enrichment failed: {e}")
        return "Summary error.", "graph TD\n    A[Error] --> B[Check Logs]", 5.0

def main():
    # ... (Keep your existing RSS fetching logic from your original file) ...
    # Assume 'all_items' is populated by your RSS/OTX logic
    all_items = [] 

    log.info("Enriching items with AI...")
    for item in all_items[:15]: # Limit to top 15 for API speed/free tier
        summary, mermaid, score = get_ai_enrichment(item['title'], item['description'])
        item['ai_summary'] = summary
        item['workflow_graph'] = mermaid
        item['severity_score'] = score
        item['ttps'] = map_ttps(item['title'] + " " + item['description'])

    # Save daily archive
    today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    archive_dir = Path(f"data/archive")
    archive_dir.mkdir(parents=True, exist_ok=True)
    
    output = {"last_updated": datetime.now(timezone.utc).isoformat(), "items": all_items}
    
    with open("data/intel.json", "w") as f:
        json.dump(output, f, indent=2)
    with open(archive_dir / f"{today}.json", "w") as f:
        json.dump(output, f, indent=2)

if __name__ == "__main__":
    main()