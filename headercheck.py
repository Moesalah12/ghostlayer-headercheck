"""Review saved HTTP response headers, or one explicitly authorized URL."""
import argparse
from email.parser import Parser
import json
from pathlib import Path
import re
import sys
import urllib.error
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def review(headers, https=True):
    headers = {key.lower(): value.strip() for key, value in headers.items()}
    findings = []

    def add(rule, severity, detail):
        findings.append({"rule": rule, "severity": severity, "detail": detail})

    csp = headers.get("content-security-policy", "")
    directives = {part.strip().split()[0].lower(): part.strip().split()[1:]
                  for part in csp.split(";") if part.strip()}
    if not csp:
        add("missing_csp", "medium", "No enforced CSP observed. Design and test a policy appropriate to the application.")
    elif any("'unsafe-inline'" in value or "'unsafe-eval'" in value for value in directives.values()):
        add("permissive_csp", "medium", "CSP contains unsafe-inline or unsafe-eval; inspect script execution controls.")
    if "frame-ancestors" not in directives and headers.get("x-frame-options", "").upper() not in ("DENY", "SAMEORIGIN"):
        add("missing_frame_control", "medium", "No recognized framing restriction observed; assess clickjacking exposure.")
    if headers.get("x-content-type-options", "").lower() != "nosniff":
        add("missing_nosniff", "low", "Set X-Content-Type-Options: nosniff and correct Content-Type values.")
    if https:
        hsts = headers.get("strict-transport-security", "")
        age = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)", hsts, re.I)
        if not age or int(age.group(1)) == 0:
            add("missing_hsts", "medium", "No positive HSTS max-age observed; validate HTTPS readiness before enabling.")
    else:
        add("http_transport", "medium", "Response observed over HTTP; HTTPS-only protections cannot be assessed here.")
    if not headers.get("referrer-policy"):
        add("missing_referrer_policy", "low", "Choose an explicit Referrer-Policy suited to the application.")
    return {"finding_count": len(findings), "findings": findings,
            "limitations": "Heuristic header review only. No exploit validation or assurance that a policy is effective."}


def read_saved(path):
    text = Path(path).read_text(encoding="utf-8")
    if text.startswith("HTTP/"):
        text = text.split("\n", 1)[1]
    message = Parser().parsestr(text)
    # Combine duplicates to preserve evidence rather than silently discarding values.
    return {name: ", ".join(message.get_all(name)) for name in message.keys()}


def fetch_headers(url, timeout=10):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("use an http(s) URL without embedded credentials")
    # Ignore environment proxy credentials; never follow redirects or disable TLS verification.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "GhostLayer-HeaderCheck/0.1"})
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as response_error:
        response = response_error
    with response:
        headers = {name: ", ".join(response.headers.get_all(name)) for name in response.headers.keys()}
        return headers, response.status, parsed.scheme == "https"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--headers", type=Path, help="offline header capture")
    source.add_argument("--url", help="one URL, redirects are not followed")
    parser.add_argument("--authorized", action="store_true", help="confirm permission to request the URL")
    parser.add_argument("--http", action="store_true", help="offline capture came from HTTP")
    args = parser.parse_args(argv)
    if args.url and not args.authorized:
        parser.error("--url requires --authorized")
    if args.url and args.http:
        parser.error("--http applies only to saved headers")
    try:
        if args.url:
            headers, status, https = fetch_headers(args.url)
        else:
            headers, status, https = read_saved(args.headers), None, not args.http
        result = review(headers, https)
        result["status_code"] = status
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, urllib.error.URLError) as exc:
        print(f"headercheck: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
