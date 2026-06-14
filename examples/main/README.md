# FIPS Main Example

A minimal single-container FIPS node that joins the public test mesh and
peers with `test-us01`.

## What it does

- Runs the `fips` daemon inside a container using the `fips-test:latest`
  image.
- Creates a persistent Nostr identity (`fips.key` / `fips.pub`) in
  `config/` so the node keeps the same `npub` across restarts.
- Exposes UDP/2121 on the host so inbound FIPS transport traffic can reach
  the container.
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

Ping the test node over the mesh:

```bash
docker compose exec fips ping6 -c 4 test-us01.fips
```

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
- This example intentionally uses only UDP transport. If your network blocks
  outbound UDP, switch the peer address to TCP port 443 or run FIPS directly
  on the host.
