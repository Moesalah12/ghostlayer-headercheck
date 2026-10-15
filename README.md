# GhostLayer HeaderCheck

**Explainable HTTP response-header review, offline by default.**

Built for Mohammad Salah’s cybersecurity engineering portfolio · GhostLayer Defense

Review a saved response-header capture for common browser security controls. An optional live mode sends one HEAD request to an explicitly authorized URL. It never follows redirects, falls back to GET, sends cookies, uses environment proxies, or disables TLS certificate verification.

## Quick start

Python 3.11+; standard library only:

```sh
python headercheck.py --headers examples/weak.txt
python headercheck.py --headers examples/hardened.txt
python -m unittest discover -s tests -v
```

The synthetic weak capture yields **5 findings**; the hardened capture yields **0 heuristic findings**. These results describe the rules implemented here, not the security of a real application. See [the sample output](examples/weak-report.json).

Live mode, only for a URL you own or have permission to assess:

```sh
python headercheck.py --url https://your-authorized-host.example --authorized
```

Replace the example host. Redirect responses are reviewed as received, with their status code; the destination is never requested. A server rejecting HEAD is reported as that response, without a GET retry. Offline captures are assumed to be HTTPS unless `--http` is supplied. Exit `0` means the review completed, even with findings; `2` means a usage or operational error.

## Checks and limits

| Control | Heuristic |
| --- | --- |
| Content-Security-Policy | Missing policy; unsafe-inline or unsafe-eval tokens |
| Framing | Recognizes frame-ancestors or DENY/SAMEORIGIN X-Frame-Options |
| MIME sniffing | Requires X-Content-Type-Options: nosniff |
| HSTS | Requires a positive max-age on an HTTPS response |
| Referrer policy | Flags a missing or empty Referrer-Policy |

The tool does not fully parse or validate CSP/referrer-policy syntax, inspect HTML meta policies, evaluate nonces or hashes, audit TLS configuration, check cookies, infer exploitability, or crawl pages. Duplicate headers are combined to retain evidence, but their browser semantics may differ. Capture exactly one response block per file. These checks are most relevant to browser-rendered HTML; APIs and other content require context. HSTS deployment needs care when subdomains have different HTTPS readiness.

Use sanitized captures. Live URLs can include sensitive query parameters; do not supply credentials or production secrets. The authorization flag is an explicit operator acknowledgement, not a technical authorization service.

See [DEVELOPMENT.md](DEVELOPMENT.md), [CONTRIBUTING.md](CONTRIBUTING.md), and [SECURITY.md](SECURITY.md). MIT licensed.

## References

- [MDN: Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy)
- [MDN: X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Content-Type-Options)
