# usque-rs on Asuswrt-Merlin

Scripts that run usque-rs as a service on an Asuswrt-Merlin router and send
the whole LAN's IPv4 traffic through the tunnel, while IPv6 and the router's
own traffic keep using the WAN directly. Written for and tested on an
RT-AX86U (firmware 388.12 and 388.13); other Broadcom HND models should be
close. A walk-through of what the scripts do, in Chinese, is in
`docs/GUIDE.zh-CN.md`.

Typical use: the WAN has slow IPv4 (for example behind carrier-grade NAT) but
good native IPv6. The tunnel connects over IPv6 (`-6`) and carries only IPv4.

## Install

1. In the router UI, under Administration > System, enable SSH and
   "JFFS custom scripts and configs".
2. Build an `aarch64-unknown-linux-musl` binary
   (`cargo zigbuild --release --target aarch64-unknown-linux-musl`) and copy
   the files:

   ```sh
   ssh admin@router 'mkdir -p /jffs/usque /jffs/scripts'
   scp -O usque-rs usque.sh admin@router:/jffs/usque/
   scp -O services-start firewall-start nat-start admin@router:/jffs/scripts/
   # only together with ipv6-bridge.sh (see the IPv6 section):
   scp -O service-event service-event-end admin@router:/jffs/scripts/
   ssh admin@router 'chmod 755 /jffs/usque/usque-rs /jffs/usque/*.sh /jffs/scripts/*-start'
   ```

   If you already have `services-start`, `firewall-start` or `nat-start`,
   append the lines from these files instead of replacing yours. The two
   `ipv6-*.sh` scripts are optional; see the IPv6 section below.
3. Register on the router (add `--jwt <token>` for Zero Trust):

   ```sh
   cd /jffs/usque && ./usque-rs register && chmod 600 config.json
   ```

4. Start it: `/jffs/usque/usque.sh start`, then check `/jffs/usque/usque.sh status`.

The service starts at boot through `services-start`.

## What `usque.sh` does

- **Tuning.** Pins the `bcmsw_rx` kernel thread to CPU 0 with a real-time
  priority, enables RPS on the WAN interface towards CPU 1, and raises
  `netdev_max_backlog`. Without this the router's CPU receive ring overflows
  at tunnel speeds; see `PERFORMANCE.md` in the repository root.
- **Tunnel.** Runs `usque-rs nativetun -6 -S` on interface `warp0` and restarts
  it if it exits.
- **Routing.** Adds a default route through `warp0` in table 211 and rules that
  send traffic from the LAN subnet there, except to private and link-local
  destinations.
- **Fallback.** Every 5 s the service pings two public addresses through the
  tunnel. The LAN rules are only in place while those pings are answered:
  after boot, and whenever the tunnel stops carrying traffic, LAN IPv4 uses
  the WAN directly instead of vanishing into a dead tunnel. Measured from a
  LAN client: 18 s without IPv4 after the tunnel died, then direct; back in
  the tunnel 6 s after it recovered. Each switch drops the connection table,
  so open connections reset and reconnect rather than hang. `FALLBACK=0`
  turns this off (LAN IPv4 then stops whenever the tunnel is down).
- **No nested WARP.** Traffic from the LAN to Cloudflare's WARP ingress ranges
  also stays on the WAN. A LAN device running its own WARP client would
  otherwise build its tunnel inside this one, and Cloudflare then stops
  forwarding the outer tunnel. Cloudflare recommends the same exclusion for
  its own on-ramps ("double encapsulation").
- **Firewall.** Masquerades traffic leaving through `warp0`, clamps the TCP MSS
  to the tunnel MTU in both directions, and drops new connections arriving
  from the tunnel towards the router itself.
- **Self-healing.** The firmware resets routing rules and firewall tables when
  the WAN comes up or the firewall is rebuilt. Every 5 s the service checks
  for its entries and puts them back.
- **Log.** Output goes to `/tmp/usque.log`, trimmed daily once it passes 512 KiB.

Optional settings go in `/jffs/usque/env`, one `NAME=value` per line:

| Setting | Effect |
|---|---|
| `ROUTE_LAN=0` | Keep the tunnel up without routing the LAN into it. |
| `FALLBACK=0` | Keep the LAN routed into the tunnel even while it is down. |
| `USQUE_GRO=0` | Disable TCP segment merging on TUN writes. |
| `USQUE_PIN=off` | Disable thread pinning. |

Other `USQUE_*` variables are listed in `PERFORMANCE.md`.

## Native IPv6 for the LAN when there is no delegated prefix

The firmware's "Native" IPv6 mode needs the upstream gateway to delegate a
prefix (DHCPv6-PD). Some gateways, cellular ones in particular, hand out a
single /64 and nothing else. Two optional scripts cover that case; use one.

### `ipv6-bridge.sh` (recommended)

Bridges IPv6, and only IPv6, between the WAN port and the LAN bridge. LAN
devices get their addresses, default route and IPv6 firewalling straight from
the upstream gateway, as if they were plugged into it. IPv4 is untouched: it
is still routed, NATed and sent through the tunnel by this router.

Setup: set IPv6 to "Disable" in the router UI (the script then manages the
router's own IPv6 on the bridge), copy `ipv6-bridge.sh` to `/jffs/usque/` and
`service-event` and `service-event-end` to `/jffs/scripts/`, and restart the
service. `usque.sh` starts the bridge before the tunnel and re-checks it
every 5 s; `ipv6-bridge.sh status` shows its state.

The two `service-event` hooks are not optional. The firmware empties every
ebtables table whenever it restarts the wireless interfaces or the network,
which is also the moment every client reconnects and asks for DHCP. With the
WAN port still in the bridge, the two networks would be joined at layer 2,
IPv4 included, until the rules were put back: each network's DHCP server
answers the other's clients. The firmware calls `service-event` before such a
restart and waits for it, so the hook takes the WAN port out of the bridge
first; `service-event-end` rebuilds the rules and only then plugs it back in.
In a test with the rule state sampled every 0.4 s, the port was never in the
bridge without the rules. If `guard rules missing` ever shows up in the system
log, something emptied the tables by a path these hooks do not cover.

What it sets up:

- ebtables rules (nat and broute tables) so that nothing but IPv6 can cross
  between WAN and LAN, and so the WAN side cannot reach the router's own SSH,
  DNS or web ports over IPv6.
- The router's own IPv6 address and default route on the LAN bridge, from the
  gateway's router advertisements.
- DNS interception (`DNS_INTERCEPT=1`, the default): the gateway advertises
  itself as an IPv6 DNS server, so LAN devices would bypass the router's
  resolver. DNS over IPv6 from the LAN, to any server, is answered by this
  router instead. Set `DNS_INTERCEPT=0` in `/jffs/usque/env` to turn it off.
- The Broadcom flow cache in "L3" mode. In the default "L2 & L3" mode it
  forwards frames between two known MAC addresses in hardware without showing
  them to ebtables, so only a device's first packets would be filtered or
  redirected. Throughput is the same in both modes.

Things to know:

- A LAN device running its own WARP client may copy the gateway's link-local
  DNS server onto its tunnel adapter, where it is unreachable, and then every
  lookup waits for a timeout. Behind this router the client is redundant
  anyway; turn it off.
- Leave the router UI on "Disable" while the bridge is in use. The other
  modes start firmware helpers that work against it.
- `ipv6-bridge.sh stop` removes the bridge and the rules and restores the
  flow cache mode, but the service puts the bridge back within seconds as long
  as the script is executable. To turn it off for good, follow the stop with
  `chmod -x /jffs/usque/ipv6-bridge.sh`, and only then pick another IPv6 mode
  in the UI.

### Firmware "IPv6 Passthrough" with `ipv6-ra-filter.sh`

The alternative keeps the firmware in charge. It works for devices that stay
on the LAN, but a device that moves between the gateway's own network and the
router's keeps its addresses, and the gateway keeps sending to where it last
saw them.

In that mode the firmware relays every Router Advertisement it hears on the
WAN to the LAN and rewrites the source to its own address. Thread border
routers on the WAN segment (HomePods, Apple TVs and the like) send RAs with a
router lifetime of 0 to announce a route. Relayed, those look like the router
withdrawing itself a moment after announcing itself, and LAN clients end up
with IPv6 addresses but no default route (on iOS the IPv6 "Router" field is
empty). The script drops zero-lifetime RAs on the WAN interface;
`firewall-start` re-applies it whenever the firewall is rebuilt.

## Uninstall

```sh
/jffs/usque/usque.sh stop
rm -rf /jffs/usque
rm /jffs/scripts/services-start /jffs/scripts/firewall-start /jffs/scripts/nat-start
rm -f /jffs/scripts/service-event /jffs/scripts/service-event-end
```

(Or remove only the usque lines if those scripts hold other commands.)
