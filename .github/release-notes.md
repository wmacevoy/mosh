Mosh with **experimental port forwarding**: TCP (`-L`, `-R`) and UDP (`-LU`, `-RU`) carried inside the mosh session.

This is an unofficial fork of [mosh](https://mosh.org). It has **not** been security-audited or reviewed by the mosh project. Documentation: https://wmacevoy.github.io/mosh/

**Port forwarding needs this build at both ends**: on your machine and on the server.

New in 1.4.0-pf.4: **`mocp`**, which copies files like `scp` but through a mosh session, so a copy survives losing the network and carries on where it left off; `mocp --auto` then keeps a directory up to date. Also `mosh --stdio host -- command`, and forwarded TCP that is about twice as fast on long paths.

New in 1.4.0-pf.3: when UDP cannot reach the server, the session is carried over ssh instead (`--relay`, on by default), and goes back to UDP when it can. A Windows server no longer needs to be told an address to listen on.

### Install

Linux (x86-64 or ARM64, glibc 2.34 or newer) and macOS (11 or later, Apple Silicon or Intel), into `~/.local/bin`, no root needed:

```
curl -fsSL https://raw.githubusercontent.com/wmacevoy/mosh/master/scripts/install.sh | sh
```

That installs the newest release. The `install.sh` attached to this release installs this one.

Windows: unpack the `msys2` zip. It contains `mosh-client.exe`, `mosh-server.exe` and the MSYS2 libraries they need; the `mosh` wrapper script also needs `perl` and `ssh`. To use a Windows machine as the server, allow inbound UDP to `mosh-server.exe` in its firewall.

Everything else: build from the source package.

The macOS programs are ad-hoc signed, not signed with an Apple Developer ID or notarized. If you download the package with a browser rather than the installer, clear macOS's quarantine with `xattr -dr com.apple.quarantine` on the unpacked directory.

### Checking a download

`SHA256SUMS` lists every file. Each was built by this repository's release workflow, which you can verify with `gh attestation verify FILE --repo wmacevoy/mosh`.
