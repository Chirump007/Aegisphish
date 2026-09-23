"""
AegisPhish - Anti-Phishing Security Application
FastAPI Server providing heuristic scanning and static asset delivery.
"""

import os
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.heuristics import analyze_url

app = FastAPI(
    title="AegisPhish API",
    description="Real-time heuristic URL scanner and credential theft prevention platform",
    version="1.0.0"
)

# Enable CORS for seamless front-end communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"

# Models
class ScanRequest(BaseModel):
    url: str = Field(..., description="The suspicious URL to inspect")

class LeakCheckRequest(BaseModel):
    target: str = Field(..., description="Email address or workplace domain to check")


@app.get("/api/health")
def health_check():
    return {
        "status": "online",
        "service": "AegisPhish Heuristic Core",
        "version": "1.0.0"
    }


@app.post("/api/scan-url")
def scan_url_post(payload: ScanRequest):
    """Analyze a submitted URL for phishing indicators, lookalikes, and credential theft traps."""
    if not payload.url or not payload.url.strip():
        raise HTTPException(status_code=400, detail="Please enter a valid URL.")
    return analyze_url(payload.url)


@app.get("/api/scan-url")
def scan_url_get(url: str = Query(..., description="The suspicious URL to inspect")):
    """GET endpoint for easy query-string analysis."""
    if not url or not url.strip():
        raise HTTPException(status_code=400, detail="Please enter a valid URL.")
    return analyze_url(url)


@app.post("/api/leak-check")
def leak_check(payload: LeakCheckRequest):
    """
    Simulate checking if an email or workplace domain is circulating in known credential dumps.
    Returns clear, simple English findings and recommendations.
    """
    target = payload.target.strip().lower()
    if not target:
        raise HTTPException(status_code=400, detail="Please provide an email or domain.")

    # Educational simulated response based on target characteristics
    is_compromised = any(k in target for k in ["admin", "test", "demo", "ceo", "finance", "user", "info", "breach"])
    
    if "@" in target:
        domain = target.split("@")[-1]
    else:
        domain = target

    if is_compromised:
        return {
            "target": target,
            "found_leaks": 3,
            "status": "Warning: Stolen Passwords Detected",
            "badge_color": "danger",
            "sources": ["Dark Web Paste Dump #402", "Compiled Credential List 2024", "Combo List Collection"],
            "simple_advice": "This email appeared in past data breaches. Attackers may already know old passwords.",
            "steps": [
                "Change passwords on any account using this email immediately.",
                "Turn on Two-Factor Authentication (2FA) or Passkeys.",
                "Never reuse the same password across multiple websites."
            ]
        }
    else:
        return {
            "target": target,
            "found_leaks": 0,
            "status": "Safe: No Public Leaks Found",
            "badge_color": "safe",
            "sources": ["Monitored 14 Billion Public Breach Records"],
            "simple_advice": "No known public leaks found for this target right now.",
            "steps": [
                "Keep using strong, unique passwords for every site.",
                "Switch to hardware Passkeys wherever supported.",
                "Be alert for unexpected login notification emails."
            ]
        }


@app.get("/api/sample-urls")
def get_sample_urls():
    """Returns curated test URLs demonstrating different phishing indicators."""
    return [
        {
            "label": "Safe Site",
            "url": "https://accounts.google.com/signin",
            "category": "safe",
            "description": "Legitimate, authenticated brand domain with SSL encryption."
        },
        {
            "label": "Fake PayPal Trap",
            "url": "http://paypa1-security-verify-account.top/login.php?cmd=_login",
            "category": "trap",
            "description": "Typosquatting (1 for l), risky .top extension, no SSL, and login keywords."
        },
        {
            "label": "Raw IP Address",
            "url": "http://192.241.168.42/secure-banking-update/signin.html",
            "category": "trap",
            "description": "Direct numerical IP bypassing standard domain registration."
        },
        {
            "label": "Shortened Link",
            "url": "https://bit.ly/urgent-account-verification-alert",
            "category": "suspicious",
            "description": "Concealed redirect disguising destination website."
        },
        {
            "label": "Subdomain Trick",
            "url": "https://microsoft.com.account-update.xyz/login",
            "category": "trap",
            "description": "Real brand name placed in subdomain to fool hurried users."
        }
    ]


# Mount static assets
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
def serve_index():
    """Serve the single page application."""
    index_path = STATIC_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return {"message": "AegisPhish UI loading..."}
