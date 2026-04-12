# nostr-punch

`nostr-punch` is a small demo binary that performs UDP hole punching using:

- Nostr relays for signaling
- STUN for reflexive address discovery
- direct UDP probe/ack exchange for the punch itself

After the punch succeeds, both peers exchange a simple UDP hello payload so
you can verify that direct communication worked.

## Build

Build just the demo binary:

```bash
cargo build --release --no-default-features --bin nostr-punch
```

The resulting binary is:

```bash
target/release/nostr-punch
```

Copy that same binary to both machines.

## Two-Machine Usage

### Responder

Run the responder first:

```bash
./nostr-punch \
  --role responder \
  --relay wss://relay.damus.io \
  --stun stun.l.google.com:19302
```

The responder prints a copyable `npub`:

```text
Responder npub:
npub1...
```

Give that `npub` to the initiator.

The responder keeps listening for more connection attempts after each
successful session.

### Initiator

Run the initiator on the other machine:

```bash
./nostr-punch \
  --role initiator \
  --relay wss://relay.damus.io \
  --responder-npub npub1... \
  --stun stun.l.google.com:19302
```

On success, both sides should log:

- service discovery / signaling
- STUN reflexive address
- hole punch succeeded
- sent and received UDP hello payload

## Common Options

```text
--role responder|initiator
--relay <url>                  Repeat to use multiple relays
--stun <host:port>             Repeat to advertise or choose multiple STUN servers
--responder-npub <npub>        Required for initiator
--secret-key <nsec-or-hex>     Optional; random key if omitted
--bind <addr>                  Default: 0.0.0.0:0
--probe-ms <ms>                Default: 200
--timeout-secs <secs>          Default: 10
--log-level <level>            Default: info
```

## Identity Behavior

If `--secret-key` is omitted, `nostr-punch` generates a random ephemeral Nostr
keypair for that run.

This is convenient for testing, but it means:

- the responder `npub` changes every time it starts
- the initiator must use the newly printed `npub`

If you want a stable identity across runs, pass `--secret-key` as either:

- `nsec1...` bech32
- 32-byte lowercase hex

## Multiple Relays and STUN Servers

You can provide multiple relays:

```bash
./nostr-punch \
  --role initiator \
  --relay wss://relay.damus.io \
  --relay wss://nos.lol \
  --relay wss://relay.primal.net \
  --responder-npub npub1...
```

You can also provide multiple STUN servers. The responder advertises all of
them, and the initiator picks the first advertised one.

## How It Works

At a high level:

1. The responder subscribes for incoming Nostr signals.
2. The responder publishes a service advertisement containing one or more STUN servers.
3. The initiator discovers that advertisement.
4. The initiator performs a STUN binding request on the same UDP socket it will later use for punching.
5. The initiator sends an offer over Nostr containing its reflexive address and session ID.
6. The responder receives the offer, performs its own STUN binding request on its punch socket, and sends an answer.
7. Both sides send UDP punch probes until both have seen a peer probe and received an ack to one of their own probes.
8. Both sides exchange a plain UDP hello payload.

The same UDP socket is used for STUN and punching so the NAT mapping stays
consistent.

## Example Successful Output

Responder:

```text
INFO responder ready; give this npub to the initiator
Responder npub:
npub1...
INFO published service advertisement
INFO received offer session_id=...
INFO STUN reflexive address reflexive=203.0.113.10:49578
INFO sent answer session_id=...
INFO hole punch succeeded peer=198.51.100.22:34797
INFO sent UDP payload peer=198.51.100.22:34797 payload=HELLO FROM RESPONDER
INFO received UDP payload peer=198.51.100.22:34797 payload=HELLO FROM INITIATOR
```

Initiator:

```text
INFO discovered service advertisement
INFO STUN reflexive address reflexive=198.51.100.22:34797
INFO sent offer session_id=...
INFO received answer session_id=... from=203.0.113.10:49578
INFO hole punch succeeded peer=203.0.113.10:49578
INFO sent UDP payload peer=203.0.113.10:49578 payload=HELLO FROM INITIATOR
INFO received UDP payload peer=203.0.113.10:49578 payload=HELLO FROM RESPONDER
```

## Troubleshooting

### `failed to connect to any relay`

Check:

- the relay URL is reachable
- you are using `wss://` for public relays
- the relay is not rate-limiting or temporarily unavailable

Public relays may return errors such as:

```text
HTTP error: 503 Service Unavailable
```

If that happens, try:

- waiting a bit before retrying
- using multiple relays
- using your own relay for repeated tests

### `service advertisement not found on any relay`

Check:

- the responder is already running
- the initiator used the correct responder `npub`
- both sides are using at least one common relay

### `STUN query failed`

Check:

- the STUN server address is valid
- outbound UDP is allowed
- local firewall rules are not blocking the socket

### `hole punch timed out`

Common reasons:

- symmetric NAT
- restrictive firewall rules
- UDP blocked in one direction
- stale or rate-limited signaling on the relay side

STUN can still report a reflexive address even when direct UDP punching is not
possible. In particular, symmetric NAT often requires a relay fallback such as
TURN rather than direct hole punching.
