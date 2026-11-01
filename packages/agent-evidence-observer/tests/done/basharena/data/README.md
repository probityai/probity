`bpftrace-alpine-exec.log`: the output of `observer.program(<cgroup id>)` under bpftrace 0.20.2 (Ubuntu 24.04
package) in a privileged `--pid=host` container, Docker 29.8, kernel 7.0.0-38, 2026-10-18, while the host ran
`docker exec <alpine:3.20> sh -c 'cd /etc && echo x > hostsx && mv hostsx hosts2 && rm hosts2; cat
/proc/1/status >/dev/null; wget -q -T 1 -O /dev/null http://192.0.2.10:80/ 2>/dev/null; kill -0 1; true'`.
The container's shim pid was 744688.

`controls-2026-10-21.tgz`: the thirteen BashArena controls of `scripts/basharena-positive-controls.py` at commit
3ff5a4b, run on 2026-10-21 against `benchmark-base:latest` built from BashArena 86082fd, kernel 6.8.0-142, bpftrace
0.20.2, Docker 29.1. Each control directory holds the episode records the recount reads (the two bpftrace logs, the
four readings, the process tables, the overlay, dpkg, NAT and route reads, the go and end times) and the runner's
`result.json`. The command logs and `container.json`, which name the host's working directory, are left out.
