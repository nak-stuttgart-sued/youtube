#!/usr/bin/env python3
"""
get_youtube_refresh_token.py

Usage:
  1. Create an OAuth 2.0 Client ID in Google Cloud Console (Desktop or Web with redirect URI http://127.0.0.1:8080/).
  2. Set environment variables or pass values when prompted: CLIENT_ID, CLIENT_SECRET, SCOPES (optional).
  3. Run locally: python3 get_youtube_refresh_token.py
  4. Browser will open; after consenting you'll see the refresh token printed in the terminal.

Notes:
 - This script spins up a temporary local HTTP server to receive the redirect.
 - Recommended redirect URI: http://127.0.0.1:8080/ (add to OAuth client in console).
"""

import os
import sys
import threading
import webbrowser
import urllib.parse as urlparse
from http.server import HTTPServer, BaseHTTPRequestHandler
import requests
import json

CLIENT_ID = os.getenv("YT_CLIENT_ID") or input("Enter OAuth CLIENT_ID: ").strip()
CLIENT_SECRET = os.getenv("YT_CLIENT_SECRET") or input("Enter OAuth CLIENT_SECRET: ").strip()
# Request youtube scope for managing live broadcasts and basic YouTube access
SCOPES = os.getenv("YT_SCOPES") or "https://www.googleapis.com/auth/youtube https://www.googleapis.com/auth/youtube.force-ssl"
PORT = int(os.getenv("YT_REDIRECT_PORT", "8080"))
REDIRECT_URI = f"http://127.0.0.1:{PORT}/"
TOKEN_URL = "https://oauth2.googleapis.com/token"
AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"

if not CLIENT_ID or not CLIENT_SECRET:
    print("CLIENT_ID and CLIENT_SECRET are required.", file=sys.stderr)
    sys.exit(1)

state_token = "state1234"  # not used for security here; fine for local one-off

class Handler(BaseHTTPRequestHandler):
    server_version = "YTRefreshTokenServer/1.0"

    def do_GET(self):
        parsed = urlparse.urlparse(self.path)
        qs = urlparse.parse_qs(parsed.query)
        if "error" in qs:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Error returned: " + qs["error"][0].encode())
            self.server.auth_code = None
            return
        code = qs.get("code", [None])[0]
        state = qs.get("state", [None])[0]
        # respond to browser
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        if code:
            self.wfile.write(b"<html><body><h2>Authorization complete. You can close this tab.</h2></body></html>")
            self.server.auth_code = code
        else:
            self.wfile.write(b"<html><body><h2>No code found in the request.</h2></body></html>")
            self.server.auth_code = None

    def log_message(self, format, *args):
        # quiet logging
        return

def build_auth_url(client_id, redirect_uri, scope, state):
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": scope,
        "access_type": "offline",
        "prompt": "consent",
        "state": state,
    }
    return AUTH_URL + "?" + urlparse.urlencode(params)

def exchange_code_for_tokens(client_id, client_secret, code, redirect_uri):
    data = {
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }
    r = requests.post(TOKEN_URL, data=data, timeout=30)
    r.raise_for_status()
    return r.json()

def main():
    auth_url = build_auth_url(CLIENT_ID, REDIRECT_URI, SCOPES, state_token)
    print("Opening browser to obtain user consent...")
    print("If browser doesn't open, paste this URL into your browser:\n", auth_url)
    # start local server
    server = HTTPServer(("127.0.0.1", PORT), Handler)
    server.auth_code = None
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    webbrowser.open(auth_url, new=1, autoraise=True)

    print(f"Waiting for authorization response on {REDIRECT_URI} ...")
    try:
        while server.auth_code is None:
            pass
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        server.shutdown()
        sys.exit(1)

    code = server.auth_code
    server.shutdown()

    if not code:
        print("No authorization code received.", file=sys.stderr)
        sys.exit(1)

    print("Exchanging code for tokens...")
    tokens = exchange_code_for_tokens(CLIENT_ID, CLIENT_SECRET, code, REDIRECT_URI)
    # tokens typically contain: access_token, expires_in, refresh_token, scope, token_type, id_token (maybe)
    refresh_token = tokens.get("refresh_token")
    if not refresh_token:
        print("No refresh_token returned. Ensure you used access_type=offline and prompt=consent and that this OAuth client is allowed to return refresh tokens.", file=sys.stderr)
        print("Full token response:\n", json.dumps(tokens, indent=2))
        sys.exit(1)

    print("\n=== REFRESH TOKEN ===")
    print(refresh_token)
    print("=====================\n")
    print("Store this refresh token securely (e.g., GitHub Secrets: YT_REFRESH_TOKEN).")
    print("\nYou can validate the token by exchanging it for an access token (example):")
    print(f"curl -s -d client_id={CLIENT_ID} -d client_secret={CLIENT_SECRET} -d refresh_token={refresh_token} -d grant_type=refresh_token https://oauth2.googleapis.com/token")

if __name__ == "__main__":
    main()