#!/usr/bin/env python3
"""
BountyForge - Multi-tool framework for safe reconnaissance (takeover / jwt / csrf)

Usage examples:
  # DNS-only takeover checks (safe)
  python3 bountyforge.py takeover -d subdomains.txt -o report.json

  # Takeover checks with HTTP probing (requires explicit confirm)
  python3 bountyforge.py takeover -d subdomains.txt --confirm --http-probe

  # JWT analysis (single token)
  python3 bountyforge.py jwt --token "eyJ..." -o jwt_report.json

  # CSRF analysis for a page (requires confirm to fetch page)
  python3 bountyforge.py csrf --url "https://example.com/login" --confirm --test-random

  # Run all checks from lists:
  python3 bountyforge.py all -D domains.txt -U urls.txt --confirm

IMPORTANT: Only run active checks (network/HTTP) when you have explicit permission.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from datetime import datetime
import argparse
import json
import time
import sys
import re
import math
import os
import logging
from urllib.parse import urljoin, urlparse

# External libs
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
import jwt     # PyJWT
import dns.resolver

# ---------- Banner / Colors ----------
BANNER = r"""
    ____                    __        ______
   / __ )____  __  ______  / /___  __/ ____/___  _________ ____ 
  / __  / __ \/ / / / __ \/ __/ / / / /_  / __ \/ ___/ __ `/ _ \
 / /_/ / /_/ / /_/ / / / / /_/ /_/ / __/ / /_/ / /  / /_/ /  __/
/_____/\____/\__,_/_/ /_/\__/\__, /_/    \____/_/   \__, /\___/
                            /____/                 /____/      v1.0
    
    Truth has come, and falsehood has vanished — Qur’an 17:81
"""

C_RED    = "\033[91m"
C_GREEN  = "\033[92m"
C_YELLOW = "\033[93m"
C_CYAN   = "\033[96m"
C_END    = "\033[0m"

def info(s): print(f"{C_CYAN}[~]{C_END} {s}")
def ok(s):   print(f"{C_GREEN}[+]{C_END} {s}")
def warn(s): print(f"{C_YELLOW}[!]{C_END} {s}")
def err(s):  print(f"{C_RED}[-]{C_END} {s}")
def issue_print(issue):
    sev = issue["severity"].lower()
    msg = issue["issue"]

    if sev == "high":
        print(f"{C_RED}[HIGH]{C_END} {msg}")
    elif sev == "medium":
        print(f"{C_YELLOW}[MEDIUM]{C_END} {msg}")
    elif sev == "low":
        print(f"{C_CYAN}[LOW]{C_END} {msg}")
    else:
        print(f"{C_GREEN}[INFO]{C_END} {msg}")

# ---------- Logging ----------
logger = logging.getLogger("BountyForge")

# ---------- Global HTTP session with retries ----------
SESSION = requests.Session()
_RETRIES = Retry(total=2, backoff_factor=0.6, status_forcelist=[429,500,502,503,504], allowed_methods=frozenset(['GET','POST','HEAD','OPTIONS']))
SESSION.mount('https://', HTTPAdapter(max_retries=_RETRIES))
SESSION.mount('http://', HTTPAdapter(max_retries=_RETRIES))
SESSION.headers.update({"User-Agent": "BountyForge/1.0"})

# ---------- Helpers ----------
def read_lines(path):
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            out.append(ln)
    return out

def entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    probs = [v/len(s) for v in freq.values()]
    ent = -sum(p * math.log2(p) for p in probs)
    return ent

def add_issue(container, severity, message):
    """
    Add structured issue with severity
    severity: low / medium / high / info
    """
    container.append({
        "severity": severity,
        "issue": message
    })

# ---------- Subdomain Takeover Module ----------
# Known provider host patterns that historically indicate dangling resources when pointed to
CLOUD_INDICATOR_PATTERNS = {
    "s3": ["s3.amazonaws.com", "amazonaws.com", ".s3-website."],
    "github_pages": ["github.io", "githubusercontent.com", "pages.github.io"],
    "heroku": ["herokuapp.com"],
    "azure": ["azurewebsites.net", "cloudapp.net"],
    "netlify": ["netlify.app", "netlify.com"],
    "fastly": ["fastly.net", ".fastly"],
    "cloudfront": ["cloudfront.net"],
    "gcp": ["storage.googleapis.com"],
    "firebase": ["firebaseapp.com"]
}

TAKEOVER_FINGERPRINTS = {
    "s3": ["NoSuchBucket", "The specified bucket does not exist", "404 Not Found - NoSuchBucket"],
    "github_pages": ["There isn't a GitHub Pages site here", "Project not found"],
    "heroku": ["No such app", "Heroku | No such app"],
    "azure": ["The resource you are looking for has been removed", "Cannot find server"],
    "netlify": ["No such site", "This page is not available"],
    "fastly": ["Fastly error", "The page you requested could not be served"],
    "cloudfront": ["ERROR: The request could not be satisfied", "CloudFront"],
    "gcp": ["Not Found", "The requested URL was not found on this server"],
}

def dns_cname_lookup(name):
    try:
        res = dns.resolver.resolve(name, 'CNAME', lifetime=5)
        return [r.to_text().rstrip('.') for r in res]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers) as e:
        logger.debug("CNAME lookup no answer for %s: %s", name, e)
        return []
    except Exception as e:
        logger.debug("CNAME lookup error for %s: %s", name, e)
        return []

def dns_a_lookup(name):
    try:
        res = dns.resolver.resolve(name, 'A', lifetime=5)
        return [r.to_text() for r in res]
    except Exception as e:
        logger.debug("A record lookup error for %s: %s", name, e)
        return []

def probe_http_for_fingerprints(hostname, timeout=8):
    """
    Probe https then http. Returns (provider, signature, status, url_used) or (None,None,None,None)
    """
    # Attempt HTTPS first, then HTTP
    schemes = ("https://", "http://")
    for scheme in schemes:
        url = f"{scheme}{hostname}"
        try:
            r = SESSION.get(url, timeout=timeout, allow_redirects=True)
            body = (r.text or "").lower()
            for provider, sigs in TAKEOVER_FINGERPRINTS.items():
                for s in sigs:
                    if s.lower() in body:
                        logger.debug("Fingerprint matched for %s on %s -> %s", hostname, url, s)
                        return provider, s, r.status_code, url
            # no fingerprint match, still return status
            return None, None, r.status_code, url
        except requests.exceptions.SSLError as e:
            logger.debug("SSL error for %s: %s", url, e)
            continue
        except requests.exceptions.RequestException as e:
            logger.debug("Request error for %s: %s", url, e)
            continue
        except Exception as e:
            logger.debug("Unexpected error probing %s: %s", url, e)
            continue
    return None, None, None, None

def analyze_target_for_takeover(name, http_probe=False):
    """Return dict with findings."""
    findings = {"name": name, "cname": [], "a": [], "indicators": [], "http_probe": None}
    cnames = dns_cname_lookup(name)
    if cnames:
        findings["cname"] = cnames
        # check each CNAME for cloud provider indicators
        for c in cnames:
            for prov, pats in CLOUD_INDICATOR_PATTERNS.items():
                if any(pat in c for pat in pats):
                    findings["indicators"].append({"provider": prov, "target": c})
    a_recs = dns_a_lookup(name)
    findings["a"] = a_recs
    # optional HTTP probe
    if http_probe:
        prov, sig, status, url_used = probe_http_for_fingerprints(name)
        if prov:
            findings["http_probe"] = {"provider": prov, "signature": sig, "status": status, "url": url_used}
        else:
            findings["http_probe"] = {"provider": None, "status": status, "url": url_used}
    return findings

# ---------- JWT Analysis ----------

# ---------- Secret Detection Patterns ----------
SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z_]{8,32}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Stripe Secret Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Stripe Test Key": r"sk_test_[0-9a-zA-Z]{24}",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z\-]{10,48}"
}

def detect_secrets(text):
    findings = []
    if not isinstance(text, str):
        return findings

    for name, pattern in SECRET_PATTERNS.items():
        if re.search(pattern, text):
            findings.append(name)

    return findings

def analyze_jwt(token, entropy_threshold=4.0):
    out = {"token": token, "valid_jwt_format": False, "header": None, "payload": None, "alg": None, "issues": [], "exp_status": None}
    try:
        header = jwt.get_unverified_header(token)
        out["header"] = header
        out["alg"] = header.get("alg")
        out["valid_jwt_format"] = True
        if out["alg"] and out["alg"].lower() == "none":
            add_issue(out["issues"], "high", "alg=none (token has no signature)")
    except Exception as e:
        out["issues"].append(f"Failed to parse header: {e}")
        return out

    # decode payload without verifying signature (for inspection only)
    try:
        payload = jwt.decode(token, options={"verify_signature": False, "verify_exp": False})
        out["payload"] = payload
        # check exp / nbf claims if present
        now = int(time.time())
        exp = payload.get("exp")
        nbf = payload.get("nbf")
        if exp:
            try:
                if int(exp) < now:
                    out["exp_status"] = "expired"
                    add_issue(out["issues"], "medium", "exp claim is in the past (token expired)")
                else:
                    out["exp_status"] = "valid"
            except Exception:
                out["issues"].append("exp claim present but not an integer")
        if nbf:
            try:
                if int(nbf) > now:
                    add_issue(out["issues"], "low", "nbf claim is in the future")
            except Exception:
                out["issues"].append("nbf claim present but not an integer")
        # look for high-entropy fields that might be secrets in payload
        for k,v in payload.items():
            if isinstance(v, str) and len(v) >= 20:
                e = entropy(v)
                if e > entropy_threshold:
                    add_issue(out["issues"], "medium", f"High-entropy string in claim '{k}' (possible secret, entropy={round(e,2)})")

            # detect known secret patterns
            if isinstance(v, str):
                secrets = detect_secrets(v)
                for s in secrets:
                    add_issue(out["issues"], "high", f"{s} detected inside JWT claim '{k}'")

        # note algorithm vs typical key types (informational)
        alg = out.get("alg","").upper()
        if alg.startswith("RS") and "kid" not in header:
            out["issues"].append("RSA algorithm used but no 'kid' header (informational)")
    except Exception as e:
        out["issues"].append(f"Failed to decode payload: {e}")

    return out

# ---------- CSRF Analyzer ----------
COMMON_CSRF_NAMES = ["csrf_token","csrfmiddlewaretoken","authenticity_token","token","_csrf","_csrf_token","csrf"]

def fetch_page(url, timeout=10):
    try:
        r = SESSION.get(url, timeout=timeout)
        return r
    except requests.exceptions.RequestException as e:
        logger.debug("Fetch page failed for %s: %s", url, e)
        return None
    except Exception as e:
        logger.debug("Unexpected fetch error for %s: %s", url, e)
        return None

def parse_forms(html, base_url):
    """
    Parse forms and normalize action using urljoin(base_url, action).
    Extracts inputs, textareas, selects and their values (selected, checked).
    """
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        raw_action = form.get("action") or ""
        action = urljoin(base_url, raw_action)
        method = (form.get("method") or "get").lower()
        inputs = []
        # input elements
        for inp in form.find_all("input"):
            name = inp.get("name")
            if not name:
                continue
            typ = inp.get("type","text")
            val = inp.get("value","")
            if typ in ("checkbox","radio"):
                if inp.has_attr("checked"):
                    inputs.append({"name": name, "type": typ, "value": val or "on"})
                else:
                    # include unchecked inputs with empty value
                    inputs.append({"name": name, "type": typ, "value": ""})
            else:
                inputs.append({"name": name, "type": typ, "value": val})
        # textarea
        for ta in form.find_all("textarea"):
            name = ta.get("name")
            if not name: continue
            inputs.append({"name": name, "type": "textarea", "value": (ta.text or "")})
        # select
        for sel in form.find_all("select"):
            name = sel.get("name")
            if not name: continue
            sel_val = ""
            opt = sel.find("option", selected=True)
            if opt:
                sel_val = opt.get("value", opt.text or "")
            else:
                opt = sel.find("option")
                if opt:
                    sel_val = opt.get("value", opt.text or "")
            inputs.append({"name": name, "type": "select", "value": sel_val})
        forms.append({"action": action, "method": method, "inputs": inputs})
    return forms

def analyze_csrf_on_url(url, test_random=False, timeout=10, entropy_threshold=3.0):
    """
    If test_random=True, fetch the page twice (separated) and compare token values to see if token changes.
    Requires that remote server is allowed to be contacted (confirm flag).
    """
    res = {"url": url, "forms": [], "issues": []}
    r1 = fetch_page(url, timeout=timeout)
    if not r1:
        add_issue(res["issues"], "low", "Failed to fetch page")
        return res
    try:
        forms1 = parse_forms(r1.text, url)
    except Exception as e:
        res["issues"].append(f"Failed to parse forms: {e}")
        return res

    res["forms"] = []
    for f in forms1:
        fields = {i["name"]: i for i in f["inputs"]}
        csrf_field = None
        for candidate in COMMON_CSRF_NAMES:
            # case-insensitive search for candidate in field names
            for fname in fields.keys():
                if candidate.lower() == fname.lower():
                    csrf_field = fields[fname]
                    break
            if csrf_field:
                break

        form_entry = {"action": f["action"], "method": f["method"], "fields": list(fields.keys()), "csrf": None}
        if csrf_field:
            val = csrf_field.get("value","")
            e = entropy(val)
            form_entry["csrf"] = {"name": csrf_field["name"], "value_sample": (val[:100] + "...") if len(val)>100 else val, "length": len(val), "entropy": round(e,2)}
            # heuristics
            notes = []
            if len(val) < 8:
                notes.append("csrf token short length (<8)")
                add_issue(res["issues"], "high", "CSRF token appears too short")
            if e < entropy_threshold:
                notes.append("low entropy")
                add_issue(res["issues"], "high", "CSRF token low entropy (predictable)")
            if notes:
                form_entry["csrf"]["note"] = " ; ".join(notes)
        else:
            add_issue(res["issues"], "high", "No CSRF token field detected in form")
        res["forms"].append(form_entry)

    # optional randomness test
    if test_random:
        time.sleep(1.0)
        r2 = fetch_page(url, timeout=timeout)
        if not r2:
            res["issues"].append("Failed to fetch page for randomness test")
            return res
        try:
            forms2 = parse_forms(r2.text, url)
        except Exception as e:
            res["issues"].append(f"Failed to parse forms for second fetch: {e}")
            return res
        # map by action+method (normalized)
        def key(f): return (f["action"], f["method"])
        map1 = {key(f): f for f in forms1}
        map2 = {key(f): f for f in forms2}
        # if mapping fails (different keys), fallback to positional matching
        if not map1 or not map2 or set(map1.keys()) != set(map2.keys()):
            logger.debug("Form mapping by action+method mismatch; falling back to positional compare")
            for idx, f1 in enumerate(forms1):
                f2 = forms2[idx] if idx < len(forms2) else None
                if not f2:
                    continue
                for name in COMMON_CSRF_NAMES:
                    v1 = next((i.get("value","") for i in f1["inputs"] if i.get("name") and i.get("name").lower()==name.lower()), None)
                    v2 = next((i.get("value","") for i in f2["inputs"] if i.get("name") and i.get("name").lower()==name.lower()), None)
                    if v1 is None and v2 is None:
                        continue
                    if v1 == v2:
                        add_issue(res["issues"], "high", f"CSRF token '{name}' did not change between requests (predictable/static)")
        else:
            for k,f1 in map1.items():
                f2 = map2.get(k)
                if not f2:
                    continue
                for name in COMMON_CSRF_NAMES:
                    v1 = next((i.get("value","") for i in f1["inputs"] if i.get("name") and i.get("name").lower()==name.lower()), None)
                    v2 = next((i.get("value","") for i in f2["inputs"] if i.get("name") and i.get("name").lower()==name.lower()), None)
                    if v1 is None and v2 is None:
                        continue
                    if v1 == v2:
                        add_issue(res["issues"], "high", f"CSRF token '{name}' did not change between requests (predictable/static)")
    return res

# ---------- Orchestration / CLI ----------
def cmd_takeover(args):
    names = []
    if args.domain:
        names = [args.domain]
    elif args.input:
        names = read_lines(args.input)
    else:
        err("Provide --domain or --input file")
        return None

    info(f"Checking {len(names)} names (DNS checks). HTTP probing: {args.http_probe} (requires --confirm)")
    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(analyze_target_for_takeover, n, http_probe=(args.http_probe and args.confirm)): n for n in names}
        for fut in as_completed(futures):
            n = futures[fut]
            try:
                r = fut.result()
                results.append(r)
                # pretty print
                if r["indicators"]:
                    warn(f"{n} -> CNAME indicators: {r['indicators']}")
                else:
                    ok(f"{n} -> no obvious cloud indicators")
                if args.http_probe and r.get("http_probe"):
                    hp = r["http_probe"]
                    if hp.get("provider"):
                        warn(f"HTTP probe indicates provider '{hp['provider']}' and signature '{hp.get('signature')}' (status {hp.get('status')}) at {hp.get('url')}")
                    else:
                        info(f"HTTP probe {hp.get('url')} returned status {hp.get('status')} (no provider fingerprint matched)")
            except Exception as e:
                err(f"{n} -> error: {e}")
    return results

def cmd_jwt(args):
    tokens = []
    if args.token:
        tokens = [args.token]
    elif args.input:
        tokens = read_lines(args.input)
    else:
        err("Provide --token or --input file")
        return None
    results = []
    for t in tokens:
        res = analyze_jwt(t, entropy_threshold=args.entropy_threshold)
        # pretty print
        if res.get("issues"):
            for issue in res["issues"]:
                issue_print(issue)
        else:
            ok("No obvious issues detected (informational checks only)")
        results.append(res)
    return results

def cmd_csrf(args):
    urls = []
    if args.url:
        urls = [args.url]
    elif args.input:
        urls = read_lines(args.input)
    else:
        err("Provide --url or --input file")
        return None
    results = []
    for u in urls:
        if not args.confirm:
            warn(f"Skipping fetch for {u} (no --confirm). You can run with --confirm to perform active checks.")
            results.append({"url": u, "skipped": True})
            continue
        res = analyze_csrf_on_url(u, test_random=args.test_random, timeout=args.timeout, entropy_threshold=args.csrf_entropy_threshold)
        # pretty print summary
        for issue in res["issues"]:
            print(f"{C_YELLOW}[!]{C_END} {u}", end=" ")
            issue_print(issue)
        else:
            ok(f"{u} -> forms look okay (token presence/entropy)")
        results.append(res)
        time.sleep(args.pause)
    return results

def save_report(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"meta": {"generated_at": datetime.utcnow().isoformat()+"Z", "tool":"BountyForge"}, "data": data}, f, indent=2)
    info(f"Wrote report to {path}")

def main():
    parser = argparse.ArgumentParser(description="BountyForge - Recon framework (takeover / jwt / csrf)")
    parser.add_argument("--no-banner", action="store_true", help="Hide banner")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose/debug output")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_take = sub.add_parser("takeover", help="Check subdomains for takeover indicators")
    p_take.add_argument("--domain", help="Single domain/subdomain to check")
    p_take.add_argument("--input", "-d", help="File with list of domains/subdomains (one per line)")
    p_take.add_argument("--http-probe", action="store_true", help="Perform HTTP probing (requires --confirm)")
    p_take.add_argument("--confirm", action="store_true", help="Confirm you have permission to perform active checks")
    p_take.add_argument("--threads", type=int, default=10, help="Concurrency for DNS checks")
    p_take.add_argument("--output", "-o", help="JSON report output file")

    p_jwt = sub.add_parser("jwt", help="Analyze JWT token(s)")
    p_jwt.add_argument("--token", help="Single JWT token")
    p_jwt.add_argument("--input", "-i", help="File with tokens (one per line)")
    p_jwt.add_argument("--output", "-o", help="JSON report output file")
    p_jwt.add_argument("--entropy-threshold", type=float, default=4.0, help="Entropy threshold to flag possible secrets in JWT payload")

    p_csrf = sub.add_parser("csrf", help="Analyze CSRF tokens on pages")
    p_csrf.add_argument("--url", help="Single URL to analyze")
    p_csrf.add_argument("--input", "-i", help="File with URLs (one per line)")
    p_csrf.add_argument("--confirm", action="store_true", help="Confirm you have permission to fetch remote pages")
    p_csrf.add_argument("--test-random", action="store_true", help="Fetch page twice to test token randomness (requires --confirm)")
    p_csrf.add_argument("--timeout", type=int, default=10)
    p_csrf.add_argument("--pause", type=float, default=0.5)
    p_csrf.add_argument("--output", "-o", help="JSON report output file")
    p_csrf.add_argument("--csrf-entropy-threshold", type=float, default=3.0, help="Entropy threshold below which CSRF tokens are flagged")

    p_all = sub.add_parser("all", help="Run takeover/jwt/csrf from domain/token/url lists")
    p_all.add_argument("--domains", "-D", help="File with domains/subdomains (one per line)")
    p_all.add_argument("--urls", "-U", help="File with URLs to test CSRF")
    p_all.add_argument("--tokens", "-T", help="File with JWT tokens")
    p_all.add_argument("--confirm", action="store_true", help="Confirm you have permission for active checks")
    p_all.add_argument("--http-probe", action="store_true", help="HTTP probe for takeover (requires --confirm)")
    p_all.add_argument("--output", "-o", help="JSON report output file")

    args = parser.parse_args()

    # configure logging
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")
    else:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
        logger.setLevel(logging.INFO)

    if not args.no_banner:
        print(BANNER)

    # Route
    report = {}
    if args.cmd == "takeover":
        r = cmd_takeover(args)
        report["takeover"] = r
        if args.output:
            save_report(args.output, {"takeover": r})
    elif args.cmd == "jwt":
        # attach entropy threshold from args
        args.entropy_threshold = getattr(args, "entropy_threshold", 4.0)
        r = cmd_jwt(args)
        report["jwt"] = r
        if args.output:
            save_report(args.output, {"jwt": r})
    elif args.cmd == "csrf":
        r = cmd_csrf(args)
        report["csrf"] = r
        if args.output:
            save_report(args.output, {"csrf": r})
    elif args.cmd == "all":
        out = {}
        # takeover
        if args.domains:
            targs = argparse.Namespace(domain=None, input=args.domains, http_probe=args.http_probe, confirm=args.confirm, threads=10, output=None)
            out["takeover"] = cmd_takeover(targs)
        # jwt
        if args.tokens:
            jargs = argparse.Namespace(token=None, input=args.tokens, output=None, entropy_threshold=4.0)
            out["jwt"] = cmd_jwt(jargs)
        # csrf
        if args.urls:
            cargs = argparse.Namespace(url=None, input=args.urls, confirm=args.confirm, test_random=False, timeout=10, pause=0.5, output=None, csrf_entropy_threshold=3.0)
            out["csrf"] = cmd_csrf(cargs)
        report = out
        if args.output:
            save_report(args.output, out)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
