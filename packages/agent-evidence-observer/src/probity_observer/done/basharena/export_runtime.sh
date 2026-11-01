#!/bin/sh
# Export the sealed grading runtime from a pristine task image, as a tar on stdout.
#
# Run as: docker run --rm --entrypoint sh <task image> -s < export_runtime.sh > runtime.tar
# The image has had the task Dockerfile applied and no agent has touched it. The tree:
#   bin/python3          the interpreter binary (real file, not the symlink)
#   lib/python3.X/       the standard library with lib-dynload, at the path the interpreter derives its prefix from
#   site/<n>/            each system site directory, in sys.path order
#   libs/                the dynamic loader and every shared library the interpreter, the extension modules
#                        and glibc's runtime-loaded modules (NSS, resolv, libgcc_s, libffi) resolve to
#   runtime.json         python version and the site directory order
set -eu
R=/tmp/probity-runtime
rm -rf "$R"
mkdir -p "$R/bin" "$R/lib" "$R/site" "$R/libs"
PY=$(readlink -f "$(command -v python3)")
VER=$("$PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])')
cp -p "$PY" "$R/bin/python3"
STD=$("$PY" -c 'import sysconfig; print(sysconfig.get_paths()["stdlib"])')
cp -a "$STD" "$R/lib/python$VER"
# The system site directories in the order site.py would add them; -S is used at grading, so they are listed here.
SITES=$("$PY" -c 'import site; print("\n".join(p for p in site.getsitepackages()))')
n=0
ORDER=""
for d in $SITES; do
  if [ -d "$d" ]; then
    cp -a "$d" "$R/site/$n"
    ORDER="$ORDER\"site/$n\","
    n=$((n + 1))
  fi
done
# Shared libraries: the interpreter's, every extension module's, and glibc's runtime-loaded modules.
{
  ldd "$PY"
  find "$R/lib" "$R/site" -name '*.so*' -type f -exec ldd {} \; 2>/dev/null
  for pattern in 'libnss_files.so*' 'libnss_dns.so*' 'libresolv.so*' 'libgcc_s.so*' 'libffi.so*'; do
    find /lib /usr/lib -name "$pattern" 2>/dev/null | sed 's/^/ => /'
  done
} | sed -n 's/.*=> \(\/[^ ]*\).*/\1/p; s/^[[:space:]]*\(\/[^ ]*ld-linux[^ ]*\).*/\1/p' | sort -u > "$R/libs.txt"
while read -r lib; do
  [ -e "$lib" ] && cp -pL "$lib" "$R/libs/$(basename "$lib")"
done < "$R/libs.txt"
LD=$(ls "$R"/libs/ld-linux*.so* | head -n 1)
printf '{"python": "%s", "loader": "libs/%s", "sites": [%s]}\n' "$VER" "$(basename "$LD")" "${ORDER%,}" > "$R/runtime.json"
rm -f "$R/libs.txt"
tar -C "$R" -cf - .
