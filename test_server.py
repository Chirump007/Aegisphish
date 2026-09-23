"""
Client test script to verify running FastAPI AegisPhish endpoints
"""
import urllib.request
import json
import time

time.sleep(1) # wait for server initialization

base = "http://127.0.0.1:8000"

def test_endpoint(url, method="GET", data=None):
    headers = {"Content-Type": "application/json"} if data else {}
    req_data = json.dumps(data).encode("utf-8") if data else None
    req = urllib.request.Request(url, data=req_data, headers=headers, method=method)
    with urllib.request.urlopen(req) as resp:
        return resp.status, resp.read().decode("utf-8")

print("Checking Health...")
status, body = test_endpoint(f"{base}/api/health")
print(f"Health Status: {status}, Body: {body}")
assert status == 200

print("\nChecking Index HTML...")
status, html_content = test_endpoint(f"{base}/")
print(f"Index Status: {status}, Length: {len(html_content)} bytes")
assert "AegisPhish" in html_content
assert "[ZERO-PHISH AI]" in html_content

print("\nTesting POST /api/scan-url...")
payload = {"url": "http://paypa1-security-verify.top/login"}
status, res = test_endpoint(f"{base}/api/scan-url", method="POST", data=payload)
data = json.loads(res)
print(f"Scan Status: {status}")
print(f"Risk Score: {data['risk_score']}%")
print(f"Status: {data['status']}")
print(f"Verdict: {data['verdict']}")
assert data['risk_score'] >= 70

print("\nTesting POST /api/leak-check...")
status, res = test_endpoint(f"{base}/api/leak-check", method="POST", data={"target": "admin@company.com"})
data = json.loads(res)
print(f"Leak Check: {data['status']}")
assert status == 200

print("\nTesting GET /api/sample-urls...")
status, res = test_endpoint(f"{base}/api/sample-urls")
samples = json.loads(res)
print(f"Sample URLs loaded: {len(samples)} items")
assert len(samples) >= 4

print("\n>>> ALL API AND FRONTEND CHECKS PASSED SUCCESSFULLY! <<<")
