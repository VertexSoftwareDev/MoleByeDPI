# Mole

*A Windows tool that gets past access blocks locally, and finds its own setting for your line.*

Mole's one-sentence goal: **you never pick a `.bat` again.** It measures what works on
your line, picks the winner, sits quietly as a service, repairs itself when it drops, and
tells you *why* when it can't get through. It is not a VPN — it does not route your traffic
through a foreign server; it only confuses the filter. Its first rule is **fail-open**: if
Mole stops, your internet keeps working.

See [Mole-Plan.md](../Mole-Plan.md) for the full design and reasoning.

## Status

Early. Building phase by phase; each phase leaves something that works on its own.

| Phase | What it delivers | State |
|-------|------------------|-------|
| **0. Foundation** | WinDivert integration, packet capture proof, admin/driver lifecycle | **done** |
| **1. Probe (CLI)** | Try the strategies, find and report the winner, say *why* | **done** |
| **2. Filter engine (core)** | The desync strategies as pure, tested transforms, applied live during a probe | **done** (battery to grow) |
| **3. DNS (DoH)** | Get past DNS hijacking; correct resolution for the probe | **done** |
| 4. Service + tray | Self-healing service, status icon, AV-conflict detection | next |
| 5. UDP/QUIC | The untouched half of the connection | — |
| 6. Diagnostics + report | "Why it failed", opt-out community report | — |
| 7. Polish | GUI, bilingual README, release flow | — |

Phases 1–3 share one engine: the probe applies each strategy through the *same*
`mole-core` code the live filter will use, so what it measures is what production
does. See [docs/findings.md](docs/findings.md) for what real lines actually did.

## Layout

- `mole-core` — the packet layer: WinDivert wrapper, IPv4/TCP/TLS inspection, elevation check.
- `mole-dns` — DoH resolver (phase 3).
- `mole-probe` — measurement engine (phase 1).
- `mole-cli` — command line: `doctor`, `capture`, later `probe`/`apply`.
- `vendor/windivert` — the signed WinDivert 2.x DLL and driver (LGPL, see its LICENSE).

## Build & run

Requires Rust (MSVC toolchain) and administrator rights (WinDivert loads a kernel driver).

```
cargo build --release -p mole-cli
```

The runner looks for `WinDivert.dll` / `WinDivert64.sys` beside the executable, then in
`vendor/windivert/x64`, then wherever `MOLE_WINDIVERT_DIR` points. From an **elevated**
prompt:

```
mole doctor              # check admin, driver, and a live capture
mole capture             # sniff outbound ClientHellos, show their SNI (traffic untouched)
mole dns <host>          # resolve over DoH (bypasses DNS hijacking)
mole probe [host ...]    # measure which bypass strategy works on this line
```

`mole probe` resolves each target over DoH, then attempts a TLS handshake with no
help (the control) and once per strategy, watching for the server's reply. It
reports one of: *not blocked*, *bypass found* (naming the winning strategy), *IP
block* (a local tool can't help), or *DPI block, no bypass yet* — and tells the
difference by measuring, never guessing. A running GoodByeDPI/zapret/ByeDPI
service rewrites the same handshakes, so `probe` warns and you should stop it first.

`doctor` on this machine, with the driver installed and one HTTPS packet caught:

```
[ok]   administrator — running elevated
[ok]   WinDivert.dll — loaded
[ok]   driver — installed and capturing
[ok]   packet capture — 104.20.23.154:443  SNI example.com
```

## Note on running alongside GoodByeDPI

If GoodByeDPI (or any other DPI-bypass tool) is active, it splits ClientHello packets
before Mole's sniffer sees them, so `capture` will show fragments without a readable SNI.
Stop the other tool to see clean captures. Mole will manage this coexistence properly in a
later phase; two tools rewriting the same handshake fight each other.

## Legal

Using a bypass tool and publishing one under your own name are different things. This repo
starts **private** by choice; revisit when it matures.
