"""minimal alert webhook receiver for e2e test: append every POST body to /out/alerts.jsonl"""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode("utf-8")
        with open("/out/alerts.jsonl", "a") as f:
            f.write(json.dumps(json.loads(body)) + "\n")
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args):
        pass


HTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
