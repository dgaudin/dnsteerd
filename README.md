# dnsteerd

**DNS-driven first-packet traffic steering daemon.**

*Version française : [README-fr.md](README-fr.md)*

dnsteerd lets you route traffic **per application** (Windows Update,
Netflix, Microsoft 365, …) from the **very first packet** of each
connection, using standard Linux building blocks (nftables + policy
routing).

## The problem

Flow-based DPI classifiers (xt_ndpi and friends) identify the application
by inspecting the first packets **of an already-open connection**: the
first packet(s) always leave through the wrong route, and a connection
that has already been routed cannot change path anymore.

## How it works

dnsteerd flips the approach: the application is known **before** the
connection exists — at DNS resolution time.

1. DNS packets (UDP/53) are intercepted through NFQUEUE (queue 200) by a
   dedicated nftables table `inet dnsteerd_filter`, created and removed
   by the daemon itself (prerouting + output hooks, priority -175,
   `bypass` = fail-open).
2. Each DNS reply is classified by **nDPI** from the queried name
   (`host_server_name`) → application id (`app_protocol`).
3. The A records of the reply are injected into the nftables set
   `ndpi_v4_<app_id>` with a timeout equal to the record TTL (bounded
   60 s – 24 h), **before** the NF_ACCEPT verdict is issued — ordering
   guarantee: by the time the client receives the answer and sends its
   SYN, the set is already populated.
4. Routing itself is the host's business: a policy-routing rule matching
   the set (`ip daddr @ndpi_v4_<id>`) marks the connection toward the
   desired routing table.

Request↔reply correlation is kept in a flow table (symmetric key,
ndpiReader-style) so the reply is attributed to the queried name even
across CDN CNAMEs.

Everything is **fail-open**: `queue ... bypass` rules (daemon gone → DNS
flows through), `NFQA_CFG_F_FAIL_OPEN` (queue full → packets pass
unclassified), `qmaxlen 8192`. DNS is never blocked; at worst
classification degrades and traffic follows the default route.

## Preparing your machine

### Kernel

- nftables (`nf_tables`) and NFQUEUE support: the `nfnetlink_queue` and
  `nft_queue` modules must be loadable **by the running kernel**.

```sh
modprobe nfnetlink_queue     # nft_queue auto-loads when the rule is installed
```

> ⚠️ Lived-through pitfall: after a kernel package upgrade **without a
> reboot**, the still-running kernel can no longer load modules
> (`/lib/modules/$(uname -r)` is gone) — any `queue` rule is then
> rejected with `ENOENT`, and since an nft batch is atomic the error
> message misleadingly points at the `add table`. Check `uname -r`
> against the installed kernel package, reboot if they differ.

### Libraries

Build: gcc, make, and development headers for:

- `libmnl`
- `libnetfilter_queue`
- `libnftables` (nftables ≥ 0.9)
- `libnftnl`
- **nDPI ≥ 5.0** (with `dns.subclassification`)

Runtime: the matching shared libraries, and **root** (netlink + nftables
sockets).

### Build

```sh
make            # produces ./dnsteerd
make install    # PREFIX=/usr/local by default
```

Platform integration: create a local `profile.h` (git-ignored) to
override any value from `defaults.h` (nftables table, runtime paths,
custom protocols file). Without `profile.h`, dnsteerd uses a dedicated
`inet dnsteerd` table and `/run/dnsteerd/`.

## Getting started

```sh
dnsteerd boot           # creates the table/sets ndpi_v4_<id> + the protocols JSON
dnsteerd daemon         # starts the daemon (-f: foreground)
```

Inspection:

```sh
dnsteerd list                # known nDPI application protocols
dnsteerd sets                # per-set IP counts, non-empty sets only (JSON)
dnsteerd set-elements <id>   # IPs of one set, with timeout/expires (JSON)
```

## Using the sets for routing

Minimal example: steer Netflix (id 133) through a second uplink.

```sh
# mark new connections toward the app's resolved IPs
nft add rule inet mytable mangle_out 'ip daddr @ndpi_v4_133 meta mark set 0x2 counter'

# route the mark through table 100
ip rule add fwmark 0x2 table 100
ip route add default via 192.0.2.254 table 100
```

(In practice you combine this with `ct mark` save/restore so the whole
connection keeps its route.)

## Custom protocols

Declare your own applications in `CUSTOM_PROTOS_PATH`
(`/etc/dnsteerd/custom_protocols.txt` by default), using the nDPI
format:

```
host:"mycdn.example.com"@MyApp
host:".update.vendor.example"@VendorUpdate
```

They get an id, a set, and show up in `dnsteerd list` like native
protocols.

## Known limitations (by design)

- **IPv4 only** for now — v4/v6 unification is planned.
- **UDP DNS only**: the DNS/TCP fallback (truncated answers) is not
  intercepted; rare in practice with EDNS0.
- **DoH/DoT are invisible**: a client resolving over encrypted DNS
  bypasses interception — its traffic follows the default route
  (degradation, never breakage).
- Re-adding an IP already present **does not refresh** its timeout
  (nf_tables behaviour); harmless in caching-resolver topologies, where
  TTLs count down in cascade.

## Credits

dnsteerd builds on **[nDPI](https://github.com/ntop/nDPI)**, the deep
packet inspection library by [ntop](https://www.ntop.org/) (LGPL-3), for
the application classification of DNS names — including its custom
protocols mechanism (`ndpi_load_protocols_file`), reused as-is.

On the kernel side it uses the [netfilter](https://netfilter.org/)
project libraries: [libmnl](https://netfilter.org/projects/libmnl/),
[libnetfilter_queue](https://netfilter.org/projects/libnetfilter_queue/),
[libnftnl](https://netfilter.org/projects/libnftnl/) and libnftables
(nftables).

## License

GPL-2.0-or-later — Copyright (C) 2026 Didier Gaudin
&lt;didier.gaudin@gmail.com&gt;
