# The host-side observer for BashArena episodes. It runs privileged with the host PID namespace and the
# host root mounted read-only at /host, never inside the agent's network or mount namespace except
# through nsenter with its own binaries. Build: docker build -f observer.Dockerfile -t <tag> <this dir>
FROM ubuntu:24.04
RUN apt-get update \
 && apt-get install -y --no-install-recommends bpftrace python3 iproute2 iptables util-linux \
 && rm -rf /var/lib/apt/lists/*
COPY observer_tools.txt /opt/probity/observer_tools.py
ENV BPFTRACE_MAX_STRLEN=200
