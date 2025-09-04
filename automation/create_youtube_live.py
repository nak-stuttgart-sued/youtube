#!/usr/bin/env python3
"""
create_youtube_live.py

Env vars required:
  YT_CLIENT_ID
  YT_CLIENT_SECRET
  YT_REFRESH_TOKEN

Optional:
  TITLE, DESCRIPTION, PRIVACY_STATUS (default unlisted)
  SCHEDULE  - "YYYY-MM-DD HH:MM" Europe/Berlin
  TARGET_HTML (default ../index.html)
  LOG_LEVEL - DEBUG|INFO|WARNING|ERROR (default INFO)
"""
import os
import sys
import json
import re
import logging
import requests
import subprocess
from pathlib import Path
from datetime import datetime, timedelta
from dateutil import tz, parser as dt_parser

# ---------- Logging setup ----------
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
logger = logging.getLogger("yt-live")
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s", "%Y-%m-%d %H:%M:%S")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
# -----------------------------------

API_BASE = "https://www.googleapis.com/youtube/v3"
TOKEN_URL = "https://oauth2.googleapis.com/token"

CLIENT_ID = os.environ.get("YT_CLIENT_ID")
CLIENT_SECRET = os.environ.get("YT_CLIENT_SECRET")
REFRESH_TOKEN = os.environ.get("YT_REFRESH_TOKEN")
TITLE = os.environ.get("TITLE") or f"NAK Stuttgart-Süd - Gottesdienst am "
DESCRIPTION = os.environ.get("DESCRIPTION", "")
PRIVACY_STATUS = os.environ.get("PRIVACY_STATUS", "unlisted")
SCHEDULE = os.environ.get("SCHEDULE")  # "YYYY-MM-DD HH:MM" Europe/Berlin
TARGET_HTML = os.environ.get("TARGET_HTML", "../index.html")

def require_envs():
    missing = [k for k in ("YT_CLIENT_ID", "YT_CLIENT_SECRET", "YT_REFRESH_TOKEN") if not os.environ.get(k)]
    if missing:
        logger.error("Missing required environment variables: %s", ", ".join(missing))
        sys.exit(1)
    logger.debug("Required environment variables present (CLIENT_ID/CLIENT_SECRET/REFRESH_TOKEN).")

def get_access_token(client_id, client_secret, refresh_token):
    logger.info("Exchanging refresh token for access token...")
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
    }
    r = requests.post(TOKEN_URL, data=data, timeout=30)
    try:
        r.raise_for_status()
    except Exception as e:
        logger.error("Failed to exchange token: %s - response: %s", e, r.text)
        raise
    tok = r.json()
    if "access_token" not in tok:
        logger.error("No access_token in token response: %s", tok)
        raise RuntimeError("No access_token returned")
    logger.info("Access token obtained (expires_in=%s)", tok.get("expires_in"))
    return tok["access_token"]

def create_live_stream(access_token, title):
    logger.info("Creating live stream (title=%s)...", title)
    url = f"{API_BASE}/liveStreams?part=snippet,cdn"
    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
    body = {
        "snippet": {"title": title},
        "cdn": {
            "frameRate": "30fps",
            "resolution": "720p",
            "ingestionType": "rtmp",
            "monitorStream": {"enableMonitorStream": True}
        }
    }
    r = requests.post(url, headers=headers, json=body, timeout=30)
    try:
        r.raise_for_status()
    except Exception as e:
        logger.error("Create liveStream failed: %s - %s", e, r.text)
        raise
    res = r.json()
    logger.debug("liveStream response: %s", json.dumps(res))
    logger.info("Created liveStream id=%s", res.get("id"))
    return res

def create_live_broadcast(access_token, title, description, start_time_rfc3339, privacy_status):
    url = f"{API_BASE}/liveBroadcasts?part=snippet,status,contentDetails"
    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
    snippet = {
        "title": title,
        "description": description,
        "scheduledStartTime": start_time_rfc3339,
        "enableAutoStart": True,
        "enableAutoStop": False
        }
    status = {
        "privacyStatus": privacy_status,
        "selfDeclaredMadeForKids": False
        }
    content_details = {
        "enableAutoStart": True,
        "enableAutoStop": False,
        "monitorStream": {
            "enableMonitorStream": True,
            "broadcastStreamDelayMs": 0
        }
    }
    body = {"snippet": snippet, "status": status, "contentDetails": content_details}
    r = requests.post(url, headers=headers, json=body, timeout=30)
    try:
        r.raise_for_status()
    except Exception as e:
        logger.error("Create Broadcast failed: %s - %s", e, r.text)
        raise
    broadcast = r.json()
    logger.debug("Created broadcast: %s", json.dumps(broadcast))
    return broadcast

    # # Now update contentDetails to disable chat
    # update_url = f"{API_BASE}/liveBroadcasts?part=contentDetails"
    # content_details = {
    #     "monitorStream": {
    #         "enableMonitorStream": True,
    #         "broadcastStreamDelayMs": 0
    #         }
    #     }
    # update_body = {"id": broadcast_id, "contentDetails": content_details}
    # r2 = requests.put(update_url, headers=headers, json=update_body, timeout=30)
    # try:
    #     r2.raise_for_status()
    # except Exception as e:
    #     logger.error("Update contentDetails failed: %s - %s", e, r2.text)
    #     raise
    # updated = r2.json()
    # logger.debug("Updated broadcast contentDetails: %s", json.dumps(updated))
    # return updated

def bind_broadcast_stream(access_token, broadcast_id, stream_id):
    logger.info("Binding broadcast %s to stream %s ...", broadcast_id, stream_id)
    url = f"{API_BASE}/liveBroadcasts/bind?id={broadcast_id}&part=id,contentDetails&streamId={stream_id}"
    headers = {"Authorization": f"Bearer {access_token}"}
    r = requests.post(url, headers=headers, timeout=30)
    try:
        r.raise_for_status()
    except Exception as e:
        logger.error("Bind failed: %s - %s", e, r.text)
        raise
    res = r.json()
    logger.debug("bind response: %s", json.dumps(res))
    logger.info("Bind successful")
    return res

def get_stream_by_name(access_token, stream_name):
    url = f"{API_BASE}/liveStreams"
    headers = {"Authorization": f"Bearer {access_token}"}
    params = {
        'part': 'id,snippet',
        'mine': 'true'
    }
    
    response = requests.get(url, headers=headers, params=params)
    
    if response.status_code == 200:
        streams = response.json().get('items', [])
        for stream in streams:
            if stream['snippet']['title'] == stream_name:
                logger.info(f"Found Livestream with given name: {stream_name}. Has ID: {stream['id']}")
                return stream  # Return the Stream Object if the title matches
    else:
        print(f"Error: {response.status_code} - {response.text}")
    
    return None  # Return None if no match is found

def parse_schedule_to_rfc3339(schedule_str):
    logger.debug("Parsing schedule: %s", schedule_str)
    if not schedule_str:
        dt = datetime.utcnow() + timedelta(minutes=5)
        rfc = dt.replace(microsecond=0).isoformat() + "Z"
        logger.info("No SCHEDULE provided; defaulting to %s", rfc)
        return rfc
    try:
        local = dt_parser.parse(schedule_str)
    except Exception as e:
        logger.error("Failed to parse SCHEDULE: %s", e)
        raise ValueError("Invalid SCHEDULE format. Use 'YYYY-MM-DD HH:MM'") from e

    berlin = tz.gettz("Europe/Berlin")
    if local.tzinfo is None:
        local = local.replace(tzinfo=berlin)
        logger.debug("Assuming naive datetime is Europe/Berlin")
    else:
        local = local.astimezone(berlin)
    utc = local.astimezone(tz.tzutc())
    rfc = utc.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    logger.info("Parsed schedule -> RFC3339 UTC: %s", rfc)
    return rfc

def write_index_html(path, watch_url):
    logger.info("Writing index HTML to %s", path)
    tpl = """<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Stuttgart-Sued Youtube</title>
    <meta http-equiv="refresh" content="5; URL={YT_WATCH_URL}">
    <link rel="canonical" href="{YT_WATCH_URL}">
    <link rel="shortcut icon" href="data:image/png;base64,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"/>
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
  </head>
  <body>
    <center>
      <h2>Sie werden in einigen Sekunden automatisch zum Gottesdienst weitergeleitet oder können untenstehenden Button drücken!</h2>
      <form action="{YT_WATCH_URL}" method="get" target="_blank">
        <button type="submit">Stuttgart-Sued - Youtube</button>
      </form>
    </center>
  </body>
</html>"""
    p = Path(path)
    if not p.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
    orig = p.read_text(encoding="utf-8") if p.exists() else ""
    bak = p.with_suffix(p.suffix + f".bak.{datetime.utcnow().strftime('%Y%m%d%H%M%S')}")
    if orig:
        bak.write_text(orig, encoding="utf-8")
        logger.info("Backup written to %s", bak)
    new = tpl.replace("{YT_WATCH_URL}", watch_url)
    p.write_text(new, encoding="utf-8")
    logger.info("index.html written")
    return str(bak) if orig else None

def main():
    require_envs()
    try:
        access_token = get_access_token(CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN)
    except Exception as e:
        logger.exception("Token exchange failed")
        sys.exit(1)

    # We can use an existing Live Stream (Key) as the key is set in Streaming Software already
    # try:
    #     stream = create_live_stream(access_token, TITLE + " (stream)")
    #     stream_id = stream["id"]
    #     ingestion = stream.get("cdn", {}).get("ingestionInfo", {})
    # except Exception:
    #     logger.exception("Failed to create live stream")
    #     sys.exit(1)

    stream = get_stream_by_name(access_token=access_token, stream_name="NAK Sued Full HD")
    if stream:
        stream_id = stream['id']
    else:
        logger.error("No Stream found for given name. Aborting...")
        sys.exit(1)

    try:
        start_rfc3339 = parse_schedule_to_rfc3339(SCHEDULE)
        start_date = datetime.fromisoformat(start_rfc3339.replace("Z", "+00:00")).strftime("%d.%m.%Y")
        broadcast = create_live_broadcast(access_token, TITLE + start_date, DESCRIPTION, start_rfc3339, PRIVACY_STATUS)
        broadcast_id = broadcast["id"]
    except Exception:
        logger.exception("Failed to create live broadcast")
        sys.exit(1)

    try:
        bind = bind_broadcast_stream(access_token, broadcast_id, stream_id)
    except Exception:
        logger.exception("Failed to bind stream to broadcast")
        sys.exit(1)

    watch_url = f"https://www.youtube.com/watch?v={broadcast_id}"
    out = {
        "broadcastId": broadcast_id,
        "streamId": stream_id,
        "watchUrl": watch_url,
    }
    logger.info("Live setup complete: watch URL=%s", watch_url)
    logger.debug("Full output: %s", json.dumps(out, indent=2))

    try:
        bak = write_index_html(TARGET_HTML, watch_url)
        if bak:
            logger.info("Backup created at %s", bak)
    except Exception:
        logger.exception("Failed to write index HTML")

if __name__ == "__main__":
    main()
