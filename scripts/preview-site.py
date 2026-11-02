#!/usr/bin/env python3
"""ローカル確認専用。公開ノードや投稿受付APIは起動しない。"""
import argparse
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]


class Handler(SimpleHTTPRequestHandler):
    MAIN_CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    FRAME_CSP = "default-src 'none'; script-src 'self' https://www.googletagmanager.com; connect-src https://www.google-analytics.com https://region1.google-analytics.com; img-src https://www.google-analytics.com https://region1.google-analytics.com; base-uri 'none'; form-action 'none'; frame-ancestors 'self'"
    AGENT_ROUTES = {
        '/agents.md': ('agents.md', 'text/markdown; charset=utf-8'),
        '/llms.txt': ('llms.txt', 'text/plain; charset=utf-8'),
        '/.well-known/idobata/agent.json': ('agent.json', 'application/json'),
        '/analytics.js': ('analytics.js', 'text/javascript; charset=utf-8'),
        '/analytics-frame.html': ('analytics-frame.html', 'text/html; charset=utf-8'),
        '/analytics-sender.js': ('analytics-sender.js', 'text/javascript; charset=utf-8'),
        '/icon.png': ('icon.webp', 'image/webp'),
        '/icon.webp': ('icon.webp', 'image/webp'),
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT / 'site'), **kwargs)

    def log_message(self, *_):
        # Preview is not an analytics source; never print raw requests or addresses.
        pass

    def end_headers(self):
        frame = urlsplit(self.path).path == '/analytics-frame.html'
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Frame-Options', 'SAMEORIGIN' if frame else 'DENY')
        self.send_header('Content-Security-Policy', self.FRAME_CSP if frame else self.MAIN_CSP)
        super().end_headers()

    def serve_asset(self, head=False):
        asset = self.AGENT_ROUTES.get(urlsplit(self.path).path)
        if asset:
            filename, content_type = asset
            try:
                data = (ROOT / 'site' / filename).read_bytes()
            except FileNotFoundError:
                self.send_error(404)
                return True
            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            if not head:
                self.wfile.write(data)
            return True
        return False

    def do_GET(self):
        if not self.serve_asset():
            super().do_GET()

    def do_HEAD(self):
        if not self.serve_asset(head=True):
            super().do_HEAD()

    def reject_write(self):
        self.send_error(405)

    do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = reject_write


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=19168)
    args = parser.parse_args()
    ThreadingHTTPServer(('127.0.0.1', args.port), Handler).serve_forever()
