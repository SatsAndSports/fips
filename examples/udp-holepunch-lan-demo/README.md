# UDP Hole-Punch LAN Demo

This example runs two FIPS nodes and a local `strfry` relay on a fixed Docker
bridge network so the peers have private IPv4 addresses in the same `/24`.
That makes it easy to observe the LAN optimization choosing the peer's private
`local_addr` instead of the public `reflexive_addr`.

## What It Demonstrates

- both peers discover each other through the local relay at `ws://relay:80`
- both peers still use public STUN servers, so a public reflexive candidate is
  available as a fallback
- the punch phase should usually log:

```text
selected punch path role=initiator selected_path=local selected_addr=172.28.0.21:...
selected punch path role=responder selected_path=local selected_addr=172.28.0.22:...
```

If the LAN path does not win, the same log line will say
`selected_path=reflexive` and show the public `ip:port` instead.

## Run

From this directory:

```bash
docker compose up --build
```

The peers wait for the local relay container to become healthy before they
start, so you should not need to manually stagger startup.

## Expected Network Layout

- relay: `172.28.0.10`
- responder: `172.28.0.21`
- initiator: `172.28.0.22`

The LAN heuristic is conservative: both peers must have RFC1918 IPv4
`local_addr` values with the same first three octets. This compose setup makes
that deterministic.

## Notes

- This demo depends on outbound UDP to the public STUN servers listed in the
  configs.
- The local relay is only for signaling; the selected punch path log tells you
  whether the final UDP path stayed private or used the public reflexive route.
