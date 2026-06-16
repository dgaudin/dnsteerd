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
3. The A/AAAA records of the reply — and the **`ipv4hint`/`ipv6hint` of
   HTTPS resource records** (type 65, RFC 9460, parsed by dnsteerd itself
   since nDPI does not decode SVCB RDATA) — are injected into the
   nftables sets `ndpi_v4_<app_id>` / `ndpi_v6_<app_id>` with a timeout
   equal to the record TTL (bounded 60 s – 24 h), **before** the
   NF_ACCEPT verdict is issued — ordering guarantee: by the time the
   client receives the answer and sends its SYN, the sets are already
   populated. (v4 and v6 elements go out in a single transactional
   netlink batch.)
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

> Only protocols nDPI can classify **from a DNS name** (host/domain
> patterns) get a set. Binary/flow-detected protocols — media/VoIP such as
> `TeamsCall` (RTP/STUN), BitTorrent, … — are never reachable from DNS and
> are excluded (their set would stay permanently empty, and they would be
> misleading in a routing UI). The routable list is generated from the nDPI
> source by `gen_dns_protocols.sh`; regenerate it when bumping nDPI. Custom
> protocols (below) are host-based by definition, hence always routable.

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
- `libnftnl`
- `libnftables` (nftables ≥ 0.9) — used off the hot path to create the
  sets and the interception ruleset
- **nDPI ≥ 5.0** (with `dns.subclassification`)

Distribution packages:

```sh
# Debian / Ubuntu
apt install build-essential libmnl-dev libnetfilter-queue-dev \
            libnftnl-dev libnftables-dev libndpi-dev

# Fedora
dnf install gcc make libmnl-devel libnetfilter_queue-devel \
            libnftnl-devel nftables-devel ndpi-devel

# RHEL / Rocky / Alma — the nftables-devel header lives in the CRB repo,
# disabled by default:
dnf config-manager --set-enabled crb
dnf install gcc make libmnl-devel libnetfilter_queue-devel \
            libnftnl-devel nftables-devel
# nDPI: from EPEL (ndpi-devel) or built from https://github.com/ntop/nDPI
```

> The libnftables header is `nftables/libnftables.h` (package
> `nftables-devel` on RHEL-likes, `libnftables-dev` on Debian). If the
> compiler can't find it, locate the right package with
> `dnf provides '*/libnftables.h'` / `apt-file search libnftables.h`.

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

### Routable-protocol list

`dns_protocols.inc` (the `dnsteerd_host_protos[]` array compiled into the
daemon) lists the host/DNS-classifiable protocols (see the note under
[How it works](#how-it-works)). It is **generated at build** by
`gen_dns_protocols.sh` from nDPI's host-match tables and is **not committed**:
it reflects your exact — possibly customized — nDPI, so it is regenerated to
stay in lock-step with the linked lib.

⚠️ **nDPI's `make install` does NOT ship those `.inc` files** (they are
internal to nDPI's own build). The Makefile regenerates `dns_protocols.inc`
when it finds them at `$(NDPI_INC)` (default `/usr/include/ndpi`); if they are
missing it **fails loudly** rather than emitting an empty list. Provide them
either by copying the tables next to the installed headers:

```sh
cp /path/to/nDPI/src/lib/ndpi_content_match.c.inc  /usr/include/ndpi/
cp -r /path/to/nDPI/src/lib/inc_generated          /usr/include/ndpi/
```

or by pointing the generator at the nDPI source tree directly:

```sh
sh gen_dns_protocols.sh /path/to/nDPI/src/lib > dns_protocols.inc
```

For a portable build without the nDPI tables, generate `dns_protocols.inc`
once and ship it with your package (it then needs refreshing on an nDPI bump).

## Getting started

```sh
dnsteerd boot           # creates the table + sets ndpi_v4_<id> / ndpi_v6_<id> + the protocols JSON
dnsteerd daemon         # starts the daemon (-f: foreground)
```

Inspection:

```sh
dnsteerd list                # known nDPI application protocols
dnsteerd sets                # per-set IP counts, non-empty sets only (JSON)
dnsteerd set-elements <id>   # IPs of one set, with timeout/expires (JSON)
dnsteerd set-elements -t <id> # same, human-readable (name, one IP per line)
```

### Running as a service

The daemon must run in the **foreground** (`-f`) under a process supervisor
so it is respawned on exit — and `dnsteerd boot` must run **once before it**
(the daemon injects into sets that `boot` creates).

```ini
# /etc/systemd/system/dnsteerd.service
[Unit]
After=nftables.service network-online.target

[Service]
ExecStartPre=/usr/local/bin/dnsteerd boot
ExecStart=/usr/local/bin/dnsteerd daemon -f
Restart=always

[Install]
WantedBy=multi-user.target
```

On a SysV/inittab system a respawn line works too — with `dnsteerd boot`
run earlier in the boot sequence:

```
dnst:23:respawn:/usr/local/bin/dnsteerd daemon -f
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

For IPv6, match the matching `@ndpi_v6_<id>` set and add an `ip -6 rule` /
`ip -6 route`. In practice you also combine this with `ct mark`
save/restore so the whole connection keeps its route.

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

### Microsoft 365 (local breakout)

A common use case is **local breakout**: steer Microsoft 365 traffic out a
dedicated/cheap internet link instead of backhauling it over an expensive
managed WAN. nDPI ships a curated, *static* snapshot of M365 domains — fine
to start, but it drifts from Microsoft's live list, and any uncovered domain
silently stays on the wrong link.

`m365-sync.sh` keeps coverage current from Microsoft's **official endpoint
API** (`endpoints.office.com`). It writes the domains as custom-protocol
entries into the conf.d directory (`CUSTOM_PROTOS_DIR`), grouped per service
into existing nDPI protocols (Exchange→`Outlook`, SharePoint/Common→
`Microsoft365`, Skype→`Teams`); edit the `map_proto` function to regroup.
It is idempotent (checks the API `/version` first) and only emits the
`Optimize`+`Allow` categories Microsoft recommends for breakout
(`M365_CATEGORIES` to change).

> This naturally **separates business M365 from bulk updates**: Microsoft
> classes its Office CDN / update endpoints (`officecdn.microsoft.com`,
> `cdn.odc.officeapps.live.com`, …) as `Default`, which the sync does **not**
> pull — so you can keep updates in their own bucket (e.g. a `WindowsUpdate`
> classification) without conflict. If you ever add `Default`, use
> `M365_EXCLUDE` (an egrep pattern) to keep those CDN/update domains out.

Refresh it from cron — the script reloads dnsteerd itself, but only when the
list actually changed:

```sh
# /etc/cron.d/dnsteerd-m365  (daily)
30 4 * * *  root  /usr/local/bin/m365-sync.sh
```

On a change the script runs a built-in reload — `dnsteerd boot` then restarts
the daemon via `pkill -x dnsteerd` (its supervisor — inittab `respawn` or
systemd `Restart=` — brings it back, reloading the conf.d). Override the
binary with `M365_DNSTEERD=/path/to/dnsteerd`, or replace the whole reload
with `M365_RELOAD="systemctl restart dnsteerd"`.

Then route the resulting protocols out the breakout link, e.g.
`ip daddr @ndpi_v4_<Microsoft365 id>` / `@ndpi_v4_<Teams id>` (see below).
dnsteerd uses the **domain** patterns from Microsoft's list (it classifies a
client's DNS lookup → injects the resolved IP); the IP ranges Microsoft also
publishes are not needed.

#### Intune (device management)

Intune is **not** in the `endpoints.office.com` API (its endpoints are
documentation-only). First check whether your nDPI already classifies it
(`dnsteerd list | grep -i intune`) — some builds/customizations ship an
`Intune` protocol; if so, just route the native `@Intune`, nothing to add.

Otherwise, Microsoft's own guidance is a stable domain catch-all —
`*.manage.microsoft.com` + `manage.microsoft.com` (and `*.dm.microsoft.com`
for Defender/EPM) — so no sync is needed: drop a static file in the conf.d
directory:

```
# protocols.d/intune.txt
host:"manage.microsoft.com",host:"dm.microsoft.com"@Intune
```

This catch-all covers enrollment, check-in, the Intune Management Extension
(app/script delivery, whose CDN is migrating to `manage.microsoft.com`) and
Remote Help. It deliberately does **not** include the Windows Update /
Delivery Optimization endpoints the Intune doc also lists — keep those in
your `WindowsUpdate` bucket. Route `@Intune` out the breakout link like the
M365 protocols.

## Known limitations (by design)

- **IPv6 extension headers are not walked**: a DNS packet transported in
  an IPv6 datagram carrying extension headers is not recognised — it
  passes unclassified (fail-open). Platforms without IPv6 can build with
  `#define DNSTEERD_IPV6 0` in `profile.h` (no v6 sets, AAAA/ipv6hint
  ignored).
- **UDP DNS only**: the DNS/TCP fallback (truncated answers) is not
  intercepted; rare in practice with EDNS0.
- **DoH/DoT are invisible**: a client resolving over encrypted DNS
  bypasses interception — its traffic follows the default route
  (degradation, never breakage). See [Dealing with DoH/DoT](#dealing-with-dohdot)
  below.
- Re-adding an IP already present **does not refresh** its timeout
  (nf_tables behaviour); harmless in caching-resolver topologies, where
  TTLs count down in cascade.

## Dealing with DoH/DoT

Encrypted DNS cannot be inspected **by design**: the reply lives inside
TLS, and reading it would require terminating the TLS session (MITM with
a CA deployed on every client) — fragile, defeated by certificate
pinning, and out of scope for a network daemon. The practical approach
is not to decrypt but to **steer clients back to plain Do53**, which
dnsteerd does see. The two protocols differ a lot here:

**DoT (RFC 7858)** uses a dedicated port, **853/tcp** — trivial to
neutralise. Blocked or rejected, clients fall back to plain DNS:

```sh
nft add rule inet mytable forward tcp dport 853 reject
```

**DoH (RFC 8484)** is HTTPS on 443, indistinguishable from regular web
traffic by port. Levers, from cleanest to bluntest:

1. **Canary domain**: answer NXDOMAIN for `use-application-dns.net`
   from your local resolver. Firefox probes this name at startup and
   silently disables its auto-DoH when it gets NXDOMAIN. With BIND:

   ```
   zone "use-application-dns.net" { type master; file "/path/to/db.empty"; };
   ```

2. **Block well-known DoH resolvers** (dns.google,
   cloudflare-dns.com, mozilla.cloudflare-dns.com, dns.quad9.net, …) by
   IP set and/or SNI. An arms race, but it covers the big ones.
3. **Endpoint policy** on managed fleets (GPO/MDM): disable DoH in
   browsers — the most reliable option when you control the clients.

Keep in mind that DoH/DoT is almost never the default on a typical
corporate client pointing at the local AD/resolver; and whatever slips
through degrades gracefully (unclassified traffic on the default
route), never breaks.

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
