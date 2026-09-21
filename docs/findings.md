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
