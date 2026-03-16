#!/bin/bash
# Collector entrypoint: starts dnsmasq, the HTTP collector, and the FIPS daemon.
dnsmasq
python3 /opt/collector/server.py &
exec fips --config /etc/fips/fips.yaml
