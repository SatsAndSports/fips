# FIPS Main Example

A minimal single-container FIPS node that joins the public test mesh,
peers with `test-us01`, resolves additional NAT-only peers via
Nostr-mediated discovery, and publishes its own UDP/TCP endpoints so
others can dial it.

## What it does

- Runs the `fips` daemon inside a container using the `fips-test:latest`
  image.
- Creates a persistent Nostr identity (`fips.key` / `fips.pub`) in
  `config/` so the node keeps the same `npub` across restarts.
- Exposes UDP/2121 and TCP/2121 on the host so inbound FIPS transport
  traffic can reach the container. UDP and TCP port namespaces are
  independent, so both can use 2121.
- Resolves NAT-only peers (`udp:nat`) from their Nostr adverts and runs
  STUN-assisted hole-punching.
- Publishes its own reachable UDP/TCP endpoints to the configured Nostr
  relays so other nodes can resolve and dial it by npub.
- Includes `fipsctl` and `fipstop` in the image for inspection.

## Prerequisites

Build the test image once from the repo root:

```bash
./testing/scripts/build.sh
```

This produces `fips-test:latest` containing `fips`, `fipsctl`, `fipstop`,
and `fips-gateway`.

## Run

```bash
cd examples/main
docker compose up -d
```

## Verify

Check that the peer link to `test-us01` is active:

```bash
docker compose exec fips fipsctl show peers
```

The output includes the static `test-us01` peer plus any `nat-peer-*`
entries that successfully punched through.

Ping the test node over the mesh:

```bash
docker compose exec fips ping6 -c 4 test-us01.fips
```

## NAT peers

The config includes five example peers discovered via
https://join.fips.network/ that advertise `udp:nat` endpoints. The daemon
resolves their Nostr adverts and attempts STUN + offer/answer hole-punching.

To add more, append another entry to `config/fips.yaml`:

```yaml
  - npub: "npub1..."
    alias: "nat-peer-N"
    via_nostr: true
    connect_policy: auto_connect
```

Then restart the container:

```bash
docker compose restart fips
```

## VPS / fixed-IP deployment

For a host with a fixed public IP and open firewall, edit
`config/fips.yaml` and uncomment the `external_addr` lines:

```yaml
transports:
  udp:
    bind_addr: "0.0.0.0:2121"
    advertise_on_nostr: true
    public: true
    external_addr: "203.0.113.45:2121"   # your public IP

  tcp:
    bind_addr: "0.0.0.0:2121"
    advertise_on_nostr: true
    external_addr: "203.0.113.45:2121"   # your public IP
```

Then allow UDP/2121 and TCP/2121 through the VPS firewall/security group
and restart:

```bash
docker compose restart fips
```

Without `external_addr`, the daemon uses STUN to discover its public IP.
STUN usually works on a VPS, but the explicit address is more reliable.

## Live TUI

`fipstop` is available inside the container. Run it interactively:

```bash
docker compose exec -it fips fipstop
```

## Stop

```bash
docker compose down
```

## Notes

- `fips.key` is a sensitive private key. It is generated on first start and
  gitignored by default.
- The container uses an ephemeral identity if `config/fips.yaml` is changed
  to `persistent: false`.
- This example uses both UDP and TCP transports. If your network blocks
  outbound UDP, TCP/2121 is the fallback. Note that restrictive corporate
  networks may only allow outbound TCP to 443/80; the public test nodes use
  TCP/443 for that reason.
- NAT traversal is best-effort. It works reliably when both sides are
  full-cone or port-restricted NATs; symmetric NAT on either side usually
  defeats the punch.
- The node publishes its own endpoint adverts (`advertise: true`). On a VPS
  with a fixed public IP, uncomment the `external_addr` lines in
  `config/fips.yaml` for deterministic adverts that skip STUN.
- To publish a `udp:nat` advert instead of direct endpoints, set
  `transports.udp.public: false`.
