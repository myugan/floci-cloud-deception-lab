#!/bin/sh
set -eu
# Orchestrator-agnostic: same redirect logic for both the Kubernetes
# and Docker Compose deployments. The one thing that differs between
# them -- an extra RETURN carve-out for log-shipping traffic reaching
# a specific IP over Tailscale -- is optional here, set via
# LOG_SHIP_ALLOW_IP. Unset (Compose's default) just skips it.
#
# Idempotent on purpose: Kubernetes init containers only ever run
# once per pod, but Compose can re-evaluate this as a dependency of
# something else (e.g. targeting one service with `up`) even after
# the netns is already configured -- re-running used to fail outright
# on the already-assigned IP address.

# Link-local IMDS address isn't routed into the netns by default —
# assign it to loopback so envoy can bind :80 there. `replace`, not
# `add`: succeeds whether or not it's already assigned.
ip addr replace 169.254.169.254/32 dev lo

add_rule() {
  # -C (check) first so re-running this script doesn't pile up
  # duplicate copies of the same rule.
  iptables -t nat -C OUTPUT "$@" 2>/dev/null || iptables -t nat -A OUTPUT "$@"
}

if [ -n "${LOG_SHIP_ALLOW_IP:-}" ]; then
  # Carve-out for log-shipping traffic to existing infrastructure —
  # not part of the AWS deception, and would otherwise get caught by
  # the blanket 443 redirect below like everything else leaving here.
  add_rule -p tcp -d "${LOG_SHIP_ALLOW_IP}/32" --dport 443 -j RETURN
fi

# No owner-uid exclusion needed here: envoy never dials out for real
# (its only cluster is floci on loopback), so there's no loop to avoid.
add_rule -p tcp --dport 443 -j REDIRECT --to-port 8443

# Catches direct :4566 calls too. Scoped to -d 127.0.0.1 specifically
# (not 0.0.0.0/0) so envoy's own forwarding to floci -- which dials
# 127.0.0.2:4566, a second loopback address outside this rule's
# match -- can't loop back into itself. An earlier uid-owner-based
# exclusion for this looked correct on paper but the OUTPUT chain's
# owner match didn't reliably attribute envoy's own outbound socket
# to uid 0 in practice (confirmed via iptables counters: the RETURN
# rule matched 0 packets while envoy's own dial still hit REDIRECT),
# causing a self-amplifying request storm. IP-scoping needs no
# owner-matching at all, so it can't have that failure mode.
add_rule -p tcp -d 127.0.0.1 --dport 4566 -j REDIRECT --to-port 8080

echo "honeypot iptables rules installed"
iptables -t nat -L OUTPUT -n --line-numbers
