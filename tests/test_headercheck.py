from contextlib import redirect_stderr
import io
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tempfile
from threading import Thread
import unittest
from headercheck import review, read_saved, fetch_headers, main


class HeaderTests(unittest.TestCase):
    def test_strong_fixture(self):
        self.assertEqual(review(read_saved("examples/hardened.txt"))["finding_count"], 0)

    def test_weak_fixture(self):
        self.assertEqual(review(read_saved("examples/weak.txt"))["finding_count"], 5)

    def test_case_insensitive_and_frame_ancestors(self):
        result = review({"CONTENT-SECURITY-POLICY": "default-src 'none'; frame-ancestors 'none'", "X-Content-Type-Options": "nosniff", "Strict-Transport-Security": "max-age=86400", "Referrer-Policy": "no-referrer"})
        self.assertEqual(result["finding_count"], 0)

    def test_disabled_hsts_and_permissive_policy(self):
        result = review({"Strict-Transport-Security": "max-age=0", "Content-Security-Policy": "script-src 'unsafe-eval'"})
        rules = [finding["rule"] for finding in result["findings"]]
        self.assertIn("missing_hsts", rules)
        self.assertIn("permissive_csp", rules)

    def test_http_does_not_claim_hsts(self):
        rules = [item["rule"] for item in review({}, https=False)["findings"]]
        self.assertIn("http_transport", rules)
        self.assertNotIn("missing_hsts", rules)

    def test_authorization_required(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exc:
            main(["--url", "https://example.com"])
        self.assertEqual(exc.exception.code, 2)

    def test_rejects_credentials_and_other_schemes(self):
        for url in ("file:///etc/passwd", "https://user:password@example.com", "invalid"):
            with self.assertRaises(ValueError):
                fetch_headers(url)

    def test_duplicates_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "headers.txt"
            path.write_text("HTTP/1.1 200 OK\nX-Test: a\nX-Test: b\n\n")
            self.assertEqual(read_saved(path)["X-Test"], "a, b")

    def test_one_head_request_and_no_redirect_following(self):
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_HEAD(self):
                requests.append(self.path)
                self.send_response(302)
                self.send_header("Location", "/must-not-be-requested")
                self.end_headers()

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            headers, status, https = fetch_headers(f"http://127.0.0.1:{server.server_port}/start")
            self.assertEqual(status, 302)
            self.assertFalse(https)
            self.assertEqual(requests, ["/start"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    unittest.main()
