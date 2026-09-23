"""
Verification test script for AegisPhish Heuristics
"""
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.heuristics import analyze_url

test_cases = [
    {
        "name": "Legitimate Google Account",
        "url": "https://accounts.google.com/signin",
        "expected_status": "Safe"
    },
    {
        "name": "Lookalike PayPal Phish",
        "url": "http://paypa1-security-verify-account.top/login.php?cmd=_login",
        "expected_status": "Phishing Trap"
    },
    {
        "name": "Direct IP Banking Phish",
        "url": "http://192.241.168.42/secure-banking/signin.html",
        "expected_status": "Phishing Trap"
    },
    {
        "name": "Shortened Link Masking",
        "url": "https://bit.ly/urgent-alert",
        "expected_status": "Suspicious"
    },
    {
        "name": "Subdomain Microsoft Spoof",
        "url": "https://microsoft.com.account-update.xyz/login",
        "expected_status": "Phishing Trap"
    }
]

print("=== Running AegisPhish Heuristic Verification ===")
all_passed = True

for case in test_cases:
    result = analyze_url(case["url"])
    print(f"\n[Test] {case['name']}")
    print(f"  URL: {case['url']}")
    print(f"  Risk Score: {result['risk_score']}% | Status: {result['status']}")
    print(f"  Threat Tags: {', '.join(result['threat_tags'])}")
    print(f"  Simple English Verdict: {result['verdict']}")
    print(f"  Action Advice: {result['action_advice']}")

    if case["expected_status"] == "Phishing Trap":
        assert result["risk_score"] >= 60, f"Expected high risk score for {case['name']}, got {result['risk_score']}"
    elif case["expected_status"] == "Safe":
        assert result["risk_score"] <= 25, f"Expected low risk score for {case['name']}, got {result['risk_score']}"

print("\n>>> All heuristic tests PASSED successfully! <<<")
