#!/usr/bin/env python3
"""
Tails a local CloudTrail-shaped log file and hands each line to
discord_alerting.py -- the Compose equivalent of manifests/alerting/
tailer.py, which tails Loki's websocket instead. Compose doesn't
assume a Loki is running anywhere; this reads the same file envoy's
FileAccessLog already writes, directly off the shared ct-logs volume.

Follows like `tail -f`: seeks to end-of-file on start (only new
events matter for live alerting) and polls for new lines, tolerating
the file not existing yet at startup since it races envoy's own
container coming up.
"""
import os
import time

import discord_alerting

LOG_PATH = os.environ.get("CT_LOG_PATH", "/var/log/floci-ct/access.log")
POLL_SECONDS = 1


def wait_for_file():
    while not os.path.exists(LOG_PATH):
        print(f"waiting for {LOG_PATH}...", flush=True)
        time.sleep(2)


def main():
    wait_for_file()
    print(f"tailing {LOG_PATH}", flush=True)
    with open(LOG_PATH, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(POLL_SECONDS)
                continue
            discord_alerting.handle_line(line.strip())


if __name__ == "__main__":
    main()
