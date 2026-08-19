#!/usr/bin/env python3
"""
Checks the honeypot's public URL on a timer and posts to Discord when
it goes down or comes back. A Running pod/container doesn't prove the
thing an attacker would actually hit still works -- a public tunnel
can drop, DNS can lag, the workload can be mid-restart. This checks
the same public path a real attacker would use, not the deployment's
internal view of itself.

Orchestrator-agnostic: HONEYPOT_URL is required, not hardcoded, since
it's inherently different per deployment (a Tailscale Funnel hostname
for the Kubernetes deployment, a droplet's own IP or domain for
Compose).

Two consecutive failures before alerting, not one -- a single blip
isn't worth a page.
"""
import os
import time
import requests

from discord_alerting import post_discord

URL = os.environ["HONEYPOT_URL"]
if not URL:
    # Compose's optional alerting profile passes this through as an
    # empty string when .env isn't set, rather than leaving it unset.
    raise RuntimeError("HONEYPOT_URL is empty -- set it in .env")
CHECK_INTERVAL_SECONDS = 60
FAILURES_BEFORE_ALERT = 2

COLOR_DOWN = 0xE74C3C
COLOR_UP = 0x2ECC71


def check() -> tuple[bool, str]:
    try:
        r = requests.get(URL, timeout=10)
        if r.status_code == 200 and "Ray Dashboard" in r.text:
            return True, f"200, title matches"
        return False, f"status={r.status_code}, unexpected body"
    except Exception as e:
        return False, str(e)[:200]


def main():
    consecutive_failures = 0
    is_down = False
    down_since = None

    while True:
        ok, detail = check()
        print(f"check: ok={ok} detail={detail}", flush=True)

        if ok:
            if is_down:
                downtime = time.time() - down_since
                post_discord({"embeds": [{
                    "title": "✅ Honeypot back up",
                    "color": COLOR_UP,
                    "fields": [
                        {"name": "URL", "value": URL, "inline": False},
                        {"name": "Downtime", "value": f"{downtime / 60:.1f} min", "inline": True},
                    ],
                    "footer": {"text": "floci-deception liveness"},
                }]})
            is_down = False
            consecutive_failures = 0
        else:
            consecutive_failures += 1
            if consecutive_failures >= FAILURES_BEFORE_ALERT and not is_down:
                is_down = True
                down_since = time.time()
                post_discord({"embeds": [{
                    "title": "\U0001f6a8 Honeypot unreachable",
                    "color": COLOR_DOWN,
                    "fields": [
                        {"name": "URL", "value": URL, "inline": False},
                        {"name": "Detail", "value": f"`{detail}`", "inline": False},
                        {"name": "Consecutive failures", "value": str(consecutive_failures), "inline": True},
                    ],
                    "footer": {"text": "floci-deception liveness"},
                }]})

        time.sleep(CHECK_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
