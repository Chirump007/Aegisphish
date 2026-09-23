"""
AegisPhish Heuristic Engine
Analyzes URLs for phishing indicators, credential harvesting, and spoofing.
Provides plain, simple English explanations for all threat tags and risk metrics.
"""

import math
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

# Popular brands commonly targeted by credential harvesters
TARGET_BRANDS = {
    "paypal": ["paypal.com"],
    "google": ["google.com", "accounts.google.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "login.microsoftonline.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "github": ["github.com"],
    "dropbox": ["dropbox.com"],
}

# Known URL shorteners that obscure destinations
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "tiny.cc", "rb.gy", "cutt.ly", "shorte.st"
}

# Risky Top-Level Domains frequently abused in phishing attacks
RISKY_TLDS = {
    "top", "xyz", "click", "buzz", "fit", "icu", "tk", "ml", "ga",
    "cf", "gq", "work", "rest", "cam", "live", "vip", "sbs", "cfd"
}

# Credential harvesting trigger words
CREDENTIAL_KEYWORDS = [
    "login", "signin", "verify", "update", "password", "account",
    "banking", "secure", "recover", "authenticate", "wallet",
    "confirm", "billing", "support", "validation", "passcode",
    "unlock", "suspension", "activity"
]

# Character substitution dictionary for typosquatting detection
LEET_MAP = {
    '0': 'o',
    '1': 'l',
    '3': 'e',
    '4': 'a',
    '5': 's',
    '8': 'b',
    '@': 'a',
    '$': 's',
}


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy to measure randomness in domain text."""
    if not text:
        return 0.0
    text = text.lower()
    length = len(text)
    freq: Dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    
    entropy = 0.0
    for count in freq.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return round(entropy, 2)


def is_ip_address(host: str) -> bool:
    """Check if the host is a raw IPv4 or IPv6 address."""
    # IPv4 regex
    ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(ipv4_pattern, host):
        parts = host.split(".")
        return all(0 <= int(p) <= 255 for p in parts)
    
    # Simple IPv6 check (enclosed in brackets or multiple colons)
    clean_host = host.strip("[]")
    if clean_host.count(":") >= 2:
        return True
    
    return False


def normalize_leet(text: str) -> str:
    """Replaces common fake number substitutions with standard letters."""
    result = []
    for ch in text.lower():
        result.append(LEET_MAP.get(ch, ch))
    return "".join(result)


def analyze_url(raw_url: str) -> Dict[str, Any]:
    """
    Performs full heuristic inspection of a URL and produces risk breakdown
    using simple, easy-to-understand English.
    """
    cleaned_url = raw_url.strip()
    if not cleaned_url:
        return {
            "error": "Please enter a valid URL to analyze.",
            "url": raw_url,
            "risk_score": 0,
            "status": "Invalid",
            "verdict": "Empty URL provided."
        }

    # Add default scheme if user pasted without protocol
    if not re.match(r"^[a-zA-Z]+://", cleaned_url):
        cleaned_url = "http://" + cleaned_url

    try:
        parsed = urlparse(cleaned_url)
    except Exception:
        return {
            "error": "Could not parse the provided URL format.",
            "url": raw_url,
            "risk_score": 50,
            "status": "Suspicious",
            "verdict": "The address format is broken or invalid."
        }

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()
    
    # Strip port if present
    hostname = netloc.split(":")[0] if ":" in netloc else netloc

    threat_tags: List[str] = []
    risk_factors: List[Dict[str, Any]] = []
    base_score = 0

    # 1. Scheme check (SSL / Plain HTTP)
    if scheme == "http":
        base_score += 20
        threat_tags.append("No Secure Padlock (HTTP)")
        risk_factors.append({
            "category": "Protocol Security",
            "level": "Medium Risk",
            "name": "Unencrypted Connection",
            "simple_explanation": "This website does not use secure HTTPS. Anyone on the same Wi-Fi can spy on what you type."
        })
    elif scheme == "https":
        risk_factors.append({
            "category": "Protocol Security",
            "level": "Low Risk",
            "name": "Secure Protocol (HTTPS)",
            "simple_explanation": "Connection is encrypted, but keep in mind that scammers can also put a fake lock on bad websites."
        })

    # 2. IP Hostname Check
    if is_ip_address(hostname):
        base_score += 40
        threat_tags.append("Direct IP Address Host")
        risk_factors.append({
            "category": "Domain Format",
            "level": "High Risk",
            "name": "Uses Numbers Instead of Domain",
            "simple_explanation": "Legitimate services use real brand names (like bank.com). Phishing traps often use raw numbers to hide who owns them."
        })

    # 3. URL Shortener Check
    is_shortener = hostname in SHORTENERS or any(hostname.endswith("." + s) for s in SHORTENERS)
    if is_shortener:
        base_score += 25
        threat_tags.append("Shortened Link Masking")
        risk_factors.append({
            "category": "Link Transparency",
            "level": "Medium Risk",
            "name": "Hidden Destination",
            "simple_explanation": "This link uses a shortener service. It conceals the real website until after you click it."
        })

    # 4. Domain Entropy (Randomness check)
    domain_entropy = calculate_entropy(hostname)
    # Exclude dots and hyphens for pure domain entropy
    pure_domain = hostname.replace(".", "").replace("-", "")
    pure_entropy = calculate_entropy(pure_domain)
    
    entropy_flag = False
    if len(pure_domain) > 10 and pure_entropy >= 3.75:
        base_score += 25
        entropy_flag = True
        threat_tags.append("High Randomness (Scrambled Domain)")
        risk_factors.append({
            "category": "Domain Structure",
            "level": "Medium Risk",
            "name": "Random Generated Name",
            "simple_explanation": "The web address looks like random keyboard mashing. Automated phishing robots often create temporary domains this way."
        })

    # 5. Risky Top Level Domain
    tld = hostname.split(".")[-1] if "." in hostname else ""
    if tld in RISKY_TLDS:
        base_score += 20
        threat_tags.append(f"Risky Domain Ending (.{tld})")
        risk_factors.append({
            "category": "Domain Extension",
            "level": "Medium Risk",
            "name": f"High-Risk .{tld} Extension",
            "simple_explanation": f"Websites ending in .{tld} are frequently used for cheap, throwaway scams."
        })

    # 6. Brand Spoofing / Typosquatting / Lookalike Check
    brand_spoofed = None
    normalized_host = normalize_leet(hostname)

    for brand, legit_domains in TARGET_BRANDS.items():
        # Check if the brand name is inside the hostname
        brand_in_host = brand in hostname or brand in normalized_host
        # Check if it actually belongs to the genuine domain
        is_legit = any(hostname == d or hostname.endswith("." + d) for d in legit_domains)

        if brand_in_host and not is_legit:
            brand_spoofed = brand
            base_score += 45
            threat_tags.append(f"Lookalike Brand Spoofing ({brand.capitalize()})")
            risk_factors.append({
                "category": "Brand Impersonation",
                "level": "Critical Risk",
                "name": f"Fake {brand.capitalize()} Website",
                "simple_explanation": f"This address claims to be {brand.capitalize()}, but does not belong to the real {brand.capitalize()} company. It wants to steal your login credentials."
            })
            break

    # 7. Credential Harvesting Keywords
    full_url_text = f"{hostname} {path} {query}".lower()
    found_keywords = [kw for kw in CREDENTIAL_KEYWORDS if kw in full_url_text]

    if found_keywords:
        # Extra points if keyword is in the host or subdomain
        keywords_in_host = [kw for kw in found_keywords if kw in hostname]
        if keywords_in_host:
            base_score += 30
            threat_tags.append("Login/Verification Keywords in Domain")
            risk_factors.append({
                "category": "Credential Trap",
                "level": "High Risk",
                "name": "Login Trap in Address",
                "simple_explanation": f"The address deliberately contains sensitive words ({', '.join(keywords_in_host[:3])}) to trick you into entering private passwords."
            })
        else:
            base_score += 15
            threat_tags.append("Credential Gathering Keywords in Path")
            risk_factors.append({
                "category": "Credential Trap",
                "level": "Medium Risk",
                "name": "Password Request Triggers",
                "simple_explanation": f"The page path looks for account actions ({', '.join(found_keywords[:3])}). Check carefully before typing passwords."
            })

    # 8. Excessive Hyphens or Subdomain Depth
    hyphen_count = hostname.count("-")
    subdomain_parts = hostname.split(".")
    
    if hyphen_count >= 3:
        base_score += 15
        threat_tags.append("Excessive Hyphens (Deceptive Name)")
        risk_factors.append({
            "category": "Visual Trick",
            "level": "Medium Risk",
            "name": "Too Many Hyphens",
            "simple_explanation": "Attackers chain together words with dashes (like secure-login-bank-alert.com) to look official."
        })

    if len(subdomain_parts) >= 4 and not is_ip_address(hostname):
        base_score += 15
        threat_tags.append("Deep Subdomain Nesting")
        risk_factors.append({
            "category": "Visual Trick",
            "level": "Medium Risk",
            "name": "Hidden Real Domain",
            "simple_explanation": "Too many dots in the address. The real website is hidden at the far right of the address."
        })

    # 9. Punycode / Homoglyph check
    if "xn--" in hostname:
        base_score += 35
        threat_tags.append("Punycode / Homoglyph Attack")
        risk_factors.append({
            "category": "Visual Trick",
            "level": "Critical Risk",
            "name": "Foreign Alphabet Lookalike",
            "simple_explanation": "This address uses foreign letters that look identical to normal English letters (like replacing 'a' with a Cyrillic letter) to deceive your eyes."
        })

    # If it is a known legitimate brand domain with no trickery
    is_known_safe = False
    for brand, legit_domains in TARGET_BRANDS.items():
        if any(hostname == d or hostname.endswith("." + d) for d in legit_domains):
            is_known_safe = True
            break
    
    if is_known_safe and not brand_spoofed:
        # Give safe bonus
        base_score = min(base_score, 10)
        if not threat_tags:
            threat_tags.append("Recognized Official Domain")

    # Clamp risk score between 0 and 100
    risk_score = min(max(base_score, 4 if scheme == "https" else 15), 100)

    # Determine status & simple English verdict
    if risk_score >= 66:
        status = "Phishing Trap"
        badge_color = "danger"
        verdict = "DANGER: High probability of credential theft. Do NOT enter usernames, passwords, or SMS codes here."
        action_advice = "Close this tab immediately. If you already entered your password, change it on the genuine official website right away."
    elif risk_score >= 26:
        status = "Suspicious"
        badge_color = "warning"
        verdict = "WARNING: This link looks suspicious. It has multiple red flags commonly seen in deceptive messages."
        action_advice = "Avoid typing sensitive passwords. Double-check who sent you this link before opening."
    else:
        status = "Safe"
        badge_color = "safe"
        verdict = "SAFE: No obvious phishing indicators detected. The domain looks normal and standard."
        action_advice = "Looks clean. Always verify the domain in your browser address bar when logging in."

    # Sub-metrics breakdown (0-100 each for UI progress bars)
    metrics = {
        "domain_reputation": max(0, 100 - (40 if brand_spoofed else 0) - (25 if tld in RISKY_TLDS else 0) - (20 if hyphen_count >= 3 else 0)),
        "entropy_safety": max(0, 100 - int(domain_entropy * 20)),
        "credential_safety": max(0, 100 - (len(found_keywords) * 25)),
        "protocol_safety": 100 if scheme == "https" else 20
    }

    return {
        "url": cleaned_url,
        "hostname": hostname,
        "scheme": scheme,
        "risk_score": risk_score,
        "status": status,
        "badge_color": badge_color,
        "verdict": verdict,
        "action_advice": action_advice,
        "threat_tags": threat_tags if threat_tags else ["Clean URL Structure"],
        "risk_factors": risk_factors,
        "metrics": metrics,
        "stats": {
            "entropy": domain_entropy,
            "keyword_count": len(found_keywords),
            "is_ip": is_ip_address(hostname),
            "is_shortener": is_shortener,
            "brand_spoofed": brand_spoofed.capitalize() if brand_spoofed else None
        }
    }
