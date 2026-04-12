# UDP Holepunch Two-Node Demo

Minimal two-machine FIPS demo for the `udp_holepunch` transport.

This setup has been validated successfully across two VPSes running the demo in
Docker with host networking. The full path has been observed end-to-end:

- responder advertisement publish
- initiator offer publish
- responder answer publish
- UDP hole punch success on both sides
- FIPS Noise handshake success
- active peer traffic after promotion

This example is split into two folders:

- `responder/` - publishes a Nostr advertisement and accepts inbound offers
- `initiator/` - discovers advertisements and auto-connects

Both sides use a shared private relay:

- `ws://80.78.18.182:7777`

## Important Caveats

- This is a manual demo, not a CI-backed end-to-end node test.
- The initiator uses `auto_connect: true`, so if you later switch back to
  public relays it may discover and attempt to connect to unrelated public
  `udp_holepunch` advertisements too.
- Run this with Docker host networking on Linux. Docker bridge NAT adds another
  translation layer and makes hole-punch behaviour harder to interpret.

## Relay Requirements

The shared relay used by this demo is:

- `ws://80.78.18.182:7777`

If you run your own relay, make sure it allows these Nostr kinds:

- `30078` - responder service advertisement
- `21059` - offer/answer signaling

These are the only kinds required for the current holepunch control plane.

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
5. Make sure UDP from the peer VPS is not blocked by host/provider firewall.

You can generate test keys with:

```bash
cargo run --no-default-features --bin fipsctl -- keygen
```

Or with an already-built binary:

```bash
fipsctl keygen
```

The demo Dockerfile also builds with `--no-default-features` intentionally so
it does not pull in BLE/dbus dependencies.

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
- `relay accepted event relay=ws://80.78.18.182:7777`
- `received signal event relay=ws://80.78.18.182:7777`
- `hole punch complete`
- `udp_holepunch responder: inbound connection established`
- `Connection promoted to active peer`

Initiator logs should show lines like:

- `Auto-connecting to discovered peer`
- `relay accepted event relay=ws://80.78.18.182:7777`
- `received signal event relay=ws://80.78.18.182:7777`
- `hole punch complete`
- `udp_holepunch outbound connection established`
- `Connection promoted to active peer`

After a successful run, both sides should show a FIPS peer and continuing
Tree/Bloom/MMP traffic.

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

## Troubleshooting

- If the relay rejects events, confirm it allows kinds `30078` and `21059`.
- If signaling succeeds but the punch times out, suspect UDP firewall/NAT
  behaviour between the two machines.
- If you switch back to public relays, expect noisy discovery and unrelated
  auto-connect attempts unless additional filtering is added.
- If Docker builds fail while generating keys locally, prefer
  `cargo run --no-default-features --bin fipsctl -- keygen`.
