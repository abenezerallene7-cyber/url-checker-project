# app.py - Final Version

import os
import base64
import requests
from flask import Flask, render_template, request, redirect

# --- Configuration ---
# IMPORTANT: You MUST replace these with your own, new API keys.
# The old keys are public and will not work.
VT_KEY = "insert your virustotal api key "
GOOGLE_KEY = "Insert your google api key"

app = Flask(__name__)

# --- API Check Functions ---

def check_virustotal(url):
    """Checks a URL against the VirusTotal database.
    Returns True if safe, False if malicious."""
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VT_KEY}
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        response = requests.get(api_url, headers=headers, timeout=7)

        if response.status_code == 404:
            print(f"[VT] Not found in database, assuming safe: {url}")
            return True  # Safe if not found
        if response.status_code != 200:
            print(f"[VT] API error ({response.status_code}), assuming safe. Key may be invalid.")
            return True  # Fail-safe: assume safe on API error

        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        print(f"[VT] {url} | Malicious detections: {malicious}")
        return malicious == 0  # True if safe, False if malicious

    except Exception as e:
        print(f"[VT] Network error, assuming safe: {e}")
        return True  # Fail-safe: assume safe on network failure

def check_google(url):
    """Checks a URL against Google Safe Browsing.
    Returns True if safe, False if malicious."""
    try:
        body = {
            "client": {"clientId": "safeurl-checker", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_KEY}"
        response = requests.post(api_url, json=body, timeout=7)

        if response.status_code != 200:
            print(f"[Google] API error ({response.status_code}), assuming safe. Key may be invalid.")
            return True  # Fail-safe: assume safe on API error

        matches = response.json()
        is_safe = not bool(matches) # True if safe (no matches), False if malicious
        print(f"[Google] {url} | Safe: {is_safe}")
        return is_safe

    except Exception as e:
        print(f"[Google] Network error, assuming safe: {e}")
        return True  # Fail-safe: assume safe on network failure

# --- Flask Routes ---

@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        raw_url = request.form.get("url", "").strip()
        if not raw_url:
            return render_template("index.html", error="Please enter a URL.")

        if not raw_url.startswith(("http://", "https://")):
            url = "https://" + raw_url
        else:
            url = raw_url
            
        print(f"\n--- Checking URL: {url} ---")
        
        vt_safe = check_virustotal(url)
        google_safe = check_google(url)

        print(f"[DECISION] VT Safe: {vt_safe}, Google Safe: {google_safe}")

        # If both services say the URL is safe, redirect the user
        if vt_safe and google_safe:
            print(f"[ACTION] URL is SAFE. Redirecting to {url}\n")
            return redirect(url)

        # Otherwise, show the warning page because at least one service flagged it
        reason = []
        if not vt_safe:
            reason.append("VirusTotal has flagged this URL as malicious.")
        if not google_safe:
            reason.append("Google Safe Browsing has flagged this URL.")
            
        print(f"[ACTION] URL is UNSAFE. Showing warning page. Reason: {reason}\n")
        return render_template("warning.html", url=url, reason=reason)

    return render_template("index.html")

@app.route("/tips")
def tips():
    return render_template("tips.html")

if __name__ == "__main__":
    app.run(debug=True)
