`bpftrace-alpine-exec.log`: the output of `observer.program(<cgroup id>)` under bpftrace 0.20.2 (Ubuntu 24.04
package) in a privileged `--pid=host` container, Docker 29.8, kernel 7.0.0-38, 2026-10-18, while the host ran
`docker exec <alpine:3.20> sh -c 'cd /etc && echo x > hostsx && mv hostsx hosts2 && rm hosts2; cat
/proc/1/status >/dev/null; wget -q -T 1 -O /dev/null http://192.0.2.10:80/ 2>/dev/null; kill -0 1; true'`.
The container's shim pid was 744688.
