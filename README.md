# Mole

A Windows tool that gets past DPI-based site blocks on your own computer, and
works out by itself which method your connection needs.

[Türkçe](README.tr.md)

![Mole's window](docs/img/gui-light-en.png)

Tools like GoodbyeDPI and zapret already know the tricks. What they leave to you
is picking the right one: a folder of `.bat` files, tried one after another,
until something works — and again whenever your provider changes its filter.
Mole does that part. It tests your connection, finds the method that gets
through, runs it as a background service, and re-tests on its own when it stops
working.

It is not a VPN. Your traffic still goes straight to the site; Mole only
reshapes the first packet of each connection so the filter can't read which
site you're asking for. If Mole stops for any reason, your connection keeps
working normally.

## Install

1. Download the latest zip from [Releases](../../releases) and unzip it.
2. Double-click **`install.cmd`** (or open **`mole-gui.exe`** and press
   *Set up protection*). Windows asks for administrator permission, because
   Mole uses a network driver.
3. That's it. Mole measures your connection (a few seconds), installs itself
   into `C:\Program Files\Mole`, and starts with Windows from then on. You can
   delete the unzipped folder.

To remove it: **Settings › Apps › Mole › Uninstall**, or `uninstall.cmd`. It
stops the service, unloads the driver and deletes its files.

To share it with a friend, send the whole zip — or just `mole.exe`,
`install.cmd` and `uninstall.cmd` (add `mole-gui.exe` for the window). The
driver is built into `mole.exe`.

## How it works

1. **Measure.** Mole looks the blocked site up over encrypted DNS (DoH), then
   opens a real TLS connection to it: once with no help, to confirm the block,
   and then once per method. A method only counts if the full handshake
   completes — a server reply followed by a broken connection is a failure, not
   a win. The first method that works is chosen; the whole run takes 1–2
   seconds because attempts run in parallel.
2. **Apply.** A Windows service applies that method to every outgoing TLS
   handshake on the machine — browsers, games and apps alike. Everything else
   passes through untouched.
3. **Watch.** Every few minutes the service checks the site it was measured on.
   If that site is blocked again, your provider has changed something: the
   service measures again and switches to whatever works now.
4. **Explain.** When nothing gets through, Mole says why: a reset right after the
   site name is seen (a DPI block), an unanswered request, a blocked IP address
   (which no local tool can get past), or a DNS lookup that fails.

The methods are the well-known ones, implemented as small, tested packet
transforms: splitting the ClientHello at the site name (into two or more
pieces, in order or reversed), and decoy ClientHellos for a harmless site sent
just ahead of the real one — with a TTL low enough to reach the filter but not
the server, a wrong sequence number, or a bad checksum — alone or combined with
a split. IPv4 and IPv6 are both handled.

What the measurements actually showed on a real line is written up in
[docs/findings.md](docs/findings.md).

## Command line

`mole.exe` does everything the window does, and more. Most commands need an
administrator prompt.

| Command | What it does |
|---|---|
| `mole install --auto` | Measure, pick the method, install and start the service |
| `mole uninstall` | Stop and remove everything |
| `mole status` | Service state, the method in use, recent service log |
| `mole test <host>` | Is this site blocked right now? (no admin needed) |
| `mole probe [host …]` | Measure which methods work, and why the others don't |
| `mole apply --auto` | Measure and apply until Ctrl+C, without installing a service |
| `mole doctor` | Check administrator rights, the driver, and packet capture |
| `mole report` | Measure everything and write an anonymous JSON report |
| `mole dns <host>` | Resolve a name over DoH |

## When it doesn't work

- **Antivirus.** Network shields (Avast, AVG, Kaspersky, ESET…) can block the
  WinDivert driver. Mole detects the common ones and says so; add an exception
  for WinDivert, or pause the shield and run the setup again.
- **Another DPI tool.** GoodbyeDPI, zapret and Mole change the same packets and
  break each other. Keep one.
- **Blocked by address.** If the site's IP address itself is blocked, nothing on
  your computer can get past it. Mole tells you when that is the case.
- **QUIC.** Browsers also reach some sites over QUIC (UDP), which Mole doesn't
  reshape. `mole install --auto --block-quic` blocks QUIC so browsers fall back
  to TCP, where Mole works.

## Building

Rust (MSVC toolchain) on Windows:

```
cargo build --release
```

This produces `target/release/mole.exe` and `mole-gui.exe`. The signed WinDivert
2.x driver and DLL are in `vendor/windivert` and get embedded into `mole.exe`.

| Crate | |
|---|---|
| `mole-core` | WinDivert wrapper, packet parsing, the methods, the live filter engine, the Windows service |
| `mole-dns` | DNS-over-HTTPS client |
| `mole-probe` | Measurement and the site check |
| `mole-cli` | The `mole` command and the service body |
| `mole-gui` | The window and tray icon |

## License

Mole is MIT-licensed. It ships [WinDivert](https://reqrypt.org/windivert.html)
unmodified, under the LGPL v3 (see `vendor/windivert/LICENSE`).

Mole does not hide who you are or what you do online. Whether using it is
allowed where you live is for you to check.
