FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iproute2 iputils-ping dnsutils openssh-client iperf3 \
        dnsmasq curl python3 && \
    rm -rf /var/lib/apt/lists/*

# dnsmasq: forward .fips to FIPS daemon, everything else to Podman DNS
RUN printf '%s\n' \
    'port=53' \
    'listen-address=127.0.0.1' \
    'bind-interfaces' \
    'server=/fips/127.0.0.1#5354' \
    'server=127.0.0.11' \
    'no-resolv' \
    >> /etc/dnsmasq.conf

COPY fips fipsctl fipstop /usr/local/bin/
RUN chmod +x /usr/local/bin/fips /usr/local/bin/fipsctl /usr/local/bin/fipstop

# Start dnsmasq in background, then run FIPS
ENTRYPOINT ["/bin/bash", "-c", "dnsmasq && exec fips --config /etc/fips/fips.yaml"]
