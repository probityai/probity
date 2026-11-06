# Witness operator

A producer can use this installed witness without receiving its signing key or store.
The host selects the key, observer pin, Unix peer UID and retained ledger head.
Missing state and a restored ledger refuse on restart.

The operator's runtime runs five native cases: a permitted write, a failed producer
after a write, witness loss before and after a write, and a process killed after
durable receipt commit but before its reply. The retained packet from that run is in
`retained/`. The installed public-key-only reader checks its history and heads,
retains the authentic head in a new consumer directory, and replays the fork refusal
without changing retained bytes.

```sh
python interop/witness-operator-2026-10-03/verify_retained.py
```

The retained copy omits the wheels and the embedded source files that are no longer
part of this tree; `retained/WITHHELD-SOURCES.json` lists each with its digest, and
the reader accepts an absent source only when that record lists the selected digest.
[Operator commands and limits](PROFILE.md) include setup, signed-head retention and
offline replay. Author-run records stay `PEER`; separate installation and UID do not
establish an outside operator.
