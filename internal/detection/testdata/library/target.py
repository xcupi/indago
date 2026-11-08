#!/usr/bin/env python3
"""Synthetic target for the cheat-sheet library validation.

Reflects ?q= into element content, but neutralises the tags the CANONICAL
planner uses (<script>, <img>, <svg>, <a>, <iframe>, <object>, <embed>, <link>,
<meta>). The library families (<details>, <video>, <audio>, <marquee>, <input>,
<select>, <textarea>, <form>, <button>) pass through, so the only way to get
execution is a library vector.
"""
import re
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# The canonical planner's tags AND its library-duplicating shapes are
# neutralised; only the library-only families (video/audio/marquee/form/button)
# survive. If the scan confirms here, the confirmation came from the library.
BLOCK = re.compile(
    r"(?i)<\s*(script|img|svg|a\b|iframe|object|embed|link|meta|body|details|input|select|textarea|marquee\b)"
)


ATTR = re.compile(r"(?i)autofocus|tabindex")


def sanitize(value: str) -> str:
    """Neutralise the canonical tags AND the canonical autofocus mechanism, so
    the only families left are the library's (video/audio/srcdoc/marquee)."""
    return ATTR.sub("noattr", BLOCK.sub("&lt;", value))


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        value = urllib.parse.parse_qs(parsed.query).get("q", [""])[0]
        body = (
            "<html><body><h1>Search</h1>"
            f'<div id="results">{sanitize(value)}</div>'
            "</body></html>"
        )
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):  # quieter output
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 19600
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
