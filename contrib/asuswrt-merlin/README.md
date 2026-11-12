# usque-rs on Asuswrt-Merlin

Scripts that run usque-rs as a service on an Asuswrt-Merlin router and send
the whole LAN's IPv4 traffic through the tunnel, while IPv6 and the router's
own traffic keep using the WAN directly. Written for and tested on an
RT-AX86U (firmware 388.12); other Broadcom HND models should be close.

Typical use: the WAN has slow IPv4 (for example behind carrier-grade NAT) but
good native IPv6. The tunnel connects over IPv6 (`-6`) and carries only IPv4.

## Install

1. In the router UI, under Administration > System, enable SSH and
   "JFFS custom scripts and configs".
2. Build or download an `aarch64-unknown-linux-musl` binary and copy the files:

   ```sh
   ssh admin@router 'mkdir -p /jffs/usque /jffs/scripts'
   scp -O usque-rs usque.sh ipv6-ra-filter.sh admin@router:/jffs/usque/
   scp -O services-start firewall-start nat-start admin@router:/jffs/scripts/
   ssh admin@router 'chmod 755 /jffs/usque/usque-rs /jffs/usque/*.sh /jffs/scripts/*-start'
   ```

   If you already have `services-start`, `firewall-start` or `nat-start`,
   append the lines from these files instead of replacing yours.
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
  destinations. If usque-rs is not running the route is gone and LAN traffic
  falls back to the WAN.
- **No nested WARP.** Traffic from the LAN to Cloudflare's WARP ingress ranges
  also stays on the WAN. A LAN device running its own WARP client would
  otherwise build its tunnel inside this one, and Cloudflare then stops
  forwarding the outer tunnel. Cloudflare recommends the same exclusion for
  its own on-ramps ("double encapsulation").
- **Firewall.** Masquerades traffic leaving through `warp0`, clamps the TCP MSS
  to the tunnel MTU in both directions, and drops new connections arriving
  from the tunnel towards the router itself.
- **Self-healing.** The firmware resets routing rules and firewall tables when
  the WAN comes up or the firewall is rebuilt. Every 15 s the service checks
  for its entries and puts them back.
- **Log.** Output goes to `/tmp/usque.log`, trimmed daily once it passes 512 KiB.

Optional settings go in `/jffs/usque/env`, one `NAME=value` per line:

| Setting | Effect |
|---|---|
| `ROUTE_LAN=0` | Keep the tunnel up without routing the LAN into it. |
| `USQUE_GRO=0` | Disable TCP segment merging on TUN writes. |
| `USQUE_PIN=off` | Disable thread pinning. |

Other `USQUE_*` variables are listed in `PERFORMANCE.md`.

## IPv6 Passthrough and vanishing default routes

`ipv6-ra-filter.sh` is only for routers that use the firmware's "IPv6
Passthrough" mode, which is the way to give LAN clients native IPv6 when the
upstream gateway hands out a single /64 and no delegated prefix.

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
```

(Or remove only the usque lines if those scripts hold other commands.)
