#!/usr/bin/env python3
"""
Tails Loki's real-time WebSocket API for {log_type="cloudtrail"} and posts
to Discord — one embed per event, as it arrives, no polling delay, no
firing/resolved lifecycle (Grafana Alerting is threshold-based and can't
embed per-event content, which is why this exists instead of an alert
rule).

Two things layered on top of the plain "one message per line" version:

- Severity coloring: purely a display concern in this script, not a Loki
  label or anything upstream (deliberately kept out of the log data model
  per earlier feedback) — just picks an embed color from the action name
  so a busy channel is scannable by severity at a glance.
- Batching: real attacker tooling (Pacu, enumerate-iam, ScoutSuite) fires
  dozens of calls in seconds. Posting one Discord message per line would
  flood the channel instantly. Events are buffered for a short window;
  a lone event still gets its full detailed embed, but a burst collapses
  into one summary message instead of N separate ones.
"""
import json
import os
import re
import threading
import time
import urllib.parse
from collections import Counter

import requests
import websocket

LOKI_WS = (
    "ws://loki.loki.svc.cluster.local:3100/loki/api/v1/tail?query="
    + urllib.parse.quote('{log_type="cloudtrail"}')
)
DISCORD_WEBHOOK = os.environ["DISCORD_WEBHOOK_URL"]

BATCH_WINDOW_SECONDS = 3

COLOR_CRITICAL = 0xE74C3C  # red    — privesc / persistence / destructive
COLOR_WARNING = 0xE67E22   # orange — general mutating calls
COLOR_INFO = 0x95A5A6      # grey   — recon / read-only, routine noise

# Purely for choosing a color — no labels, no Loki, nothing upstream.
_CRITICAL_RE = re.compile(
    r"^(Attach.*Policy|Put.*Policy|Detach.*Policy|.*PolicyVersion|AssumeRole.*|"
    r"CreateLoginProfile|UpdateLoginProfile|AddUserToGroup|UpdateAssumeRolePolicy|"
    r"CreateAccessKey|UpdateAccessKey|Delete.*|Terminate.*|Revoke.*)$"
)
_INFO_RE = re.compile(r"^(Get.*|List.*|Describe.*|Lookup.*)$")


def severity_color(event_name: str) -> int:
    if _CRITICAL_RE.match(event_name):
        return COLOR_CRITICAL
    if _INFO_RE.match(event_name):
        return COLOR_INFO
    return COLOR_WARNING


def _truncate(s: str, limit: int) -> str:
    return s if len(s) <= limit else s[: limit - 1] + "…"


def format_embed(d: dict) -> dict:
    ua = d.get("userAgent", "?")
    if len(ua) > 200:
        ua = ua[:200] + "…"

    service_short = d.get("eventSource", "?").split(".")[0]
    action = d.get("eventName", "?")
    title = f"🚨 {service_short}:{action} — canary key triggered"

    # Source IP dropped too, same reasoning as Access Key: with a single
    # decoy pod, it's always the same value — no differentiating signal.
    fields = [
        {"name": "Service", "value": f"`{d.get('eventSource', '?')}`", "inline": True},
        {"name": "Action", "value": f"**{action}**", "inline": True},
        {"name": "Region", "value": f"`{d.get('awsRegion', '?')}`", "inline": True},
    ]

    params = d.get("requestParameters")
    if params:
        params_str = _truncate(json.dumps(params), 1000)
        fields.append({"name": "Parameters", "value": f"```json\n{params_str}\n```", "inline": False})

    fields.append({"name": "User-Agent", "value": f"```{ua}```", "inline": False})

    return {
        "title": title,
        "color": severity_color(action),
        "fields": fields,
        "footer": {"text": "floci-deception"},
        "timestamp": d.get("eventTime"),
    }


def format_batch_embed(events: list) -> dict:
    counts = Counter(f"{e.get('eventSource', '?').split('.')[0]}:{e.get('eventName', '?')}" for e in events)
    # Escalate to the worst severity present in the burst.
    color = COLOR_INFO
    for e in events:
        c = severity_color(e.get("eventName", "?"))
        if c == COLOR_CRITICAL:
            color = COLOR_CRITICAL
            break
        if c == COLOR_WARNING and color != COLOR_CRITICAL:
            color = COLOR_WARNING

    lines = [f"`{n}` × {c}" for n, c in counts.most_common(15)]

    return {
        "title": f"🚨 Burst: {len(events)} canary key calls in {BATCH_WINDOW_SECONDS}s",
        "color": color,
        "fields": [
            {"name": "Calls", "value": "\n".join(lines), "inline": False},
        ],
        "footer": {"text": "floci-deception"},
        "timestamp": events[-1].get("eventTime"),
    }


def post_discord(payload: dict):
    try:
        r = requests.post(DISCORD_WEBHOOK, json=payload, timeout=10)
        print(f"posted to discord: status={r.status_code}", flush=True)
    except Exception as e:
        print(f"discord post failed: {e}", flush=True)


class Batcher:
    """Collects events for BATCH_WINDOW_SECONDS. A lone event in the
    window gets its full detailed embed; two or more collapse into one
    summary message."""

    def __init__(self):
        self._lock = threading.Lock()
        self._pending: list = []
        thread = threading.Thread(target=self._flush_loop, daemon=True)
        thread.start()

    def add(self, event: dict):
        with self._lock:
            self._pending.append(event)

    def _flush_loop(self):
        while True:
            time.sleep(BATCH_WINDOW_SECONDS)
            with self._lock:
                batch, self._pending = self._pending, []
            if not batch:
                continue
            if len(batch) == 1:
                post_discord({"embeds": [format_embed(batch[0])]})
            else:
                post_discord({"embeds": [format_batch_embed(batch)]})


batcher = Batcher()


def on_message(ws, message):
    data = json.loads(message)
    for stream in data.get("streams", []):
        for _ts, line in stream.get("values", []):
            try:
                batcher.add(json.loads(line))
            except Exception:
                post_discord({"content": f"cloudtrail activity (unparsed): {line[:200]}"})


def on_error(ws, error):
    print(f"ws error: {error}", flush=True)


def on_close(ws, *_a):
    print("ws closed", flush=True)


def on_open(ws):
    print(f"ws connected: {LOKI_WS}", flush=True)


def main():
    while True:
        ws = websocket.WebSocketApp(
            LOKI_WS,
            on_open=on_open,
            on_message=on_message,
            on_error=on_error,
            on_close=on_close,
        )
        ws.run_forever()
        print("reconnecting in 5s", flush=True)
        time.sleep(5)


if __name__ == "__main__":
    main()
