# Findings — measured, not assumed

A running log of what the probe actually measured on real lines. Each entry is a
fact we can act on, with the date and how it was observed.

## 2026-09-21 · Home line (ISP TBD), Roblox/Discord

**Setup.** Mole phases 0–3 built. GoodByeDPI stopped during measurement so its
handshake rewriting wouldn't skew the numbers. DoH via Cloudflare.

**What resolved.** `www.roblox.com → 128.116.13.3`, `discord.com → 162.159.x`,
`www.wikipedia.org → 185.15.59.224`. DoH worked cleanly against both Cloudflare
and Google, so DNS hijacking is not the (only) mechanism here — the block is DPI.

**Block confirmed, and proven to be SNI-based.** Control (a raw ClientHello) to
Roblox is reset immediately (~130 ms, one RTT) right after the ClientHello.
Decisive cross-check, same server IP `128.116.13.3`, GoodByeDPI stopped:

| SNI presented        | Result                              |
|----------------------|-------------------------------------|
| `www.roblox.com`     | connection reset (RST)              |
| `www.wikipedia.org`  | TLS 1.3 handshake **completed**     |

Same IP, same port — only the server name differs. So the server is innocent; a
middlebox resets on the blocked SNI. Hiding the SNI *would* let the connection
through. Wikipedia itself is not blocked on this line (control succeeded).

**Initial strategy battery did not beat it.** Every strategy in the phase-0
battery (split at SNI, split at 2, disorder, fake with bad-checksum / low-TTL /
wrong-seq, and fake+split combinations) still drew the same ~130 ms RST as the
control. The filter *did* apply on the wire (debug-confirmed: the ClientHello was
caught and the reshaped segments were injected, the original never leaked). So
this line's DPI reassembles the TCP stream and is not fooled by these variants.

**Why GoodByeDPI works here but our battery doesn't (yet).** GoodByeDPI's Turkey
preset (`-5`) leans on a fake packet whose TTL is *auto-detected* to land between
the client and the DPI but short of the server. Our low-TTL decoys used fixed
guesses (3, 5) that almost certainly don't match this line's hop distance to the
middlebox. **Next step: auto-TTL discovery** — sweep the decoy TTL to find where
the DPI sits — is the highest-value strategy addition. The probe is exactly the
instrument to develop and verify it against, one measured attempt at a time.

**Takeaways for the design.**
- The probe's classification is trustworthy: it called Wikipedia *not blocked*,
  Roblox *DPI-blocked with a RST*, and the cross-check confirmed the RST is the
  DPI, not the server.
- "Say why" already pays off: we can tell an SNI/DPI reset apart from an IP block
  or a DNS lie, on this line, today.
- Auto-TTL fake tuning is the gap between "measures correctly" and "gets you in".

## 2026-09-21 (later) · Same line — BYPASS WORKING, end to end

Two fixes turned "measures correctly" into "gets you in", both verified live
(elevated, Avast paused):

**1. The decoy needed a benign name.** The fake decoys had been repeating the
*real* (blocked) SNI, poisoning nothing. Carrying a benign `www.google.com`
ClientHello at the real sequence number, plus a TTL sweep (2–9), and the line
opens: `fake:ttl3..9` and `fakesplit:ttl3..9:sni` all complete a full TLS 1.3
handshake to Roblox and Discord. Proven with a real SChannel client, service
running vs. removed:

| Mole service | www.roblox.com (by IP, real SNI) |
|--------------|----------------------------------|
| running `fake:ttl3` | **TLS 1.3 completed** |
| removed | connection reset (blocked again) |

`mole install --auto` measured the line, picked `fake:ttl3`, installed the
self-healing service, and the blocked sites opened. Uninstall restored the block
and left nothing behind. The whole product works.

**2. A reply is not a handshake.** `fake:badsum` *replied* but the handshake then
broke — this NIC's TCP checksum offload repairs the decoy's deliberately-wrong
checksum on the way out, so the decoy reaches the server as a valid duplicate and
corrupts the stream. The probe used to count that first reply as a win (a false
positive). It now drives the **full** handshake, so `fake:badsum` is correctly
reported as *"SNI got through but the handshake broke (checksum offload)"* and a
TTL-based fake — which actually completes — wins instead. Lesson baked in: measure
the usable outcome, not the first encouraging sign.

**Where the DPI sits.** Every TTL from 3 upward works, 2 doesn't — so the middlebox
is ~2 hops out on this line, and a fixed low TTL like 3–5 is plenty here. The sweep
finds it without needing to know that in advance.
