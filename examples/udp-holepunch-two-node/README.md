# UDP Holepunch Two-Node Demo

Minimal two-machine FIPS smoke test for the `udp_holepunch` transport.

This example is split into two folders:

- `responder/` - publishes a Nostr advertisement and accepts inbound offers
- `initiator/` - discovers advertisements and auto-connects

Both sides use public relays:

- `wss://nostr.chaima.info`
- `wss://relay.primal.net`
- `wss://nos.lol`
- `wss://relay.damus.io`

## Important Caveats

- This is a manual smoke test, not a CI-backed end-to-end node test.
- The initiator uses `auto_connect: true`, so on public relays it may discover
  and attempt to connect to other public `udp_holepunch` advertisements too.
- Run this with Docker host networking on Linux. Docker bridge NAT adds another
  translation layer and makes hole-punch behaviour harder to interpret.

## Folder Layout

```text
examples/udp-holepunch-two-node/
├── Dockerfile
├── README.md
├── responder/
│   ├── docker-compose.yml
│   ├── fips.yaml
│   └── secrets/
└── initiator/
    ├── docker-compose.yml
    ├── fips.yaml
    └── secrets/
```

`secrets/` is present for future cleanup work. Right now both configs use
explicit `nsec` values, so nothing in this demo writes into that directory.

## Setup

1. Put a different `nsec` in each side's `fips.yaml`.
2. Copy the `responder/` folder to one machine.
3. Copy the `initiator/` folder to the other machine.
4. Make sure both machines can reach the relays and STUN servers.

You can generate test keys with:

```bash
cargo run --bin fipsctl -- keygen
```

Or with an already-built binary:

```bash
fipsctl keygen
```

## Run

Responder machine:

```bash
cd examples/udp-holepunch-two-node/responder
docker compose up --build
```

Initiator machine:

```bash
cd examples/udp-holepunch-two-node/initiator
docker compose up --build
```

## What To Watch For

Responder logs should show lines like:

- `udp_holepunch responder: advertisement published`
- `udp_holepunch responder: listening for offers`
- `udp_holepunch responder: inbound connection established`

Initiator logs should show lines like:

- `Auto-connecting to discovered peer`
- `udp_holepunch outbound connection established`

After a successful punch, both sides should show a FIPS peer.

Check status:

```bash
docker compose exec fips fipsctl show status
docker compose exec fips fipsctl show peers
docker compose exec fips fipsctl show links
```

## Compose Notes

- `network_mode: host` is intentional.
- `tun` and `dns` are disabled to keep this test focused on the transport and
  handshake path.
- No static `peers:` section is used. The initiator connects via discovery.
