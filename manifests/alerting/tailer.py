#!/usr/bin/env python3
"""
Tails Loki's real-time WebSocket API for {log_type="cloudtrail"} and
hands each line to shared/discord_alerting.py. Formatting, retries,
and the dedup guard all live there -- this file is only "how events
arrive" for the Kubernetes deployment specifically. Compose's tailer
(shared/file-tailer.py) tails the local log file directly instead,
since Compose doesn't assume a Loki is available.
"""
import json
import time
import urllib.parse

import websocket

import discord_alerting

LOKI_WS = (
    "ws://loki.loki.svc.cluster.local:3100/loki/api/v1/tail?query="
    + urllib.parse.quote('{log_type="cloudtrail"}')
)


def on_message(ws, message):
    data = json.loads(message)
    for stream in data.get("streams", []):
        for _ts, line in stream.get("values", []):
            discord_alerting.handle_line(line)


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
