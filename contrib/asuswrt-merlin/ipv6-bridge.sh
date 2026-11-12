#!/bin/sh
# Native IPv6 for the LAN when the upstream gateway offers a single /64 and no
# delegated prefix: bridge IPv6 (and only IPv6) between the WAN port and the
# LAN bridge. LAN devices then talk to the upstream gateway directly for IPv6,
# as if they were plugged into it, while IPv4 keeps being routed and NATed by
# this router.
#
# This replaces the firmware's "IPv6 Passthrough" mode, which relays router
# advertisements and proxies neighbour discovery instead. That breaks for a
# device that moves between the two networks (it keeps its addresses, and the
# upstream gateway keeps sending to where it last saw them), and it makes the
# router look for LAN hosts on the WAN. Set IPv6 to "Disable" in the router UI
# when using this script; it manages the router's own IPv6 on the bridge.
#
# usage: ipv6-bridge.sh start|stop|ensure|status
#
# What is not bridged: anything that is not IPv6. ARP, DHCP and all other IPv4
# traffic can never cross, in either direction.
#
# Side effects worth knowing:
#  - LAN devices' IPv6 is firewalled by the upstream gateway, not this router.
#  - With DNS_INTERCEPT=1, DNS over IPv6 from LAN devices (to any server) is
#    answered by this router's resolver, so it follows the same DNS policy as
#    IPv4. Set DNS_INTERCEPT=0 in /jffs/usque/env to leave it alone.

DIR=/jffs/usque
DNS_INTERCEPT=1
[ -f "$DIR/env" ] && . "$DIR/env"

WAN=$(nvram get wan0_ifname 2>/dev/null); WAN=${WAN:-eth0}
BR=$(nvram get lan_ifname 2>/dev/null); BR=${BR:-br0}
# TCP ports of this router that the WAN side must not reach over IPv6.
GUARD_TCP="22 53 80 443 8443"

conf() { echo "$2" > "/proc/sys/net/ipv6/conf/$BR/$1" 2>/dev/null; }
in_bridge() { [ -d "/sys/class/net/$BR/brif/$WAN" ]; }
has_jump() { ebtables -t "$1" -L "$2" 2>/dev/null | grep -q -- "-j $3"; }

chain() { # chain <table> <name>: create (or empty) a user chain that falls through
    ebtables -t "$1" -N "$2" -P RETURN 2>/dev/null || ebtables -t "$1" -F "$2"
}

build_rules() {
    # Non-IPv6 frames arriving on the WAN port are routed, never bridged.
    chain broute v6br
    ebtables -t broute -A v6br -i "$WAN" -p ! IPv6 -j DROP

    chain filter v6br_fw
    ebtables -A v6br_fw -o "$WAN" -p ! IPv6 -j DROP
    ebtables -A v6br_fw -i "$WAN" -p ! IPv6 -j DROP

    chain filter v6br_out
    ebtables -A v6br_out -o "$WAN" -p ! IPv6 -j DROP

    chain filter v6br_in
    ebtables -A v6br_in -i "$WAN" -p ! IPv6 -j DROP
    for p in $GUARD_TCP; do
        ebtables -A v6br_in -i "$WAN" -p IPv6 --ip6-proto tcp --ip6-dport "$p" -j DROP
    done
    ebtables -A v6br_in -i "$WAN" -p IPv6 --ip6-proto udp --ip6-dport 53 -j DROP

    chain nat v6br
    if [ "$DNS_INTERCEPT" = 1 ]; then
        # Hand LAN DNS-over-IPv6 frames to this router instead of bridging them on.
        ebtables -t nat -A v6br -i ! "$WAN" -p IPv6 --ip6-proto udp --ip6-dport 53 -j redirect --redirect-target ACCEPT
        ebtables -t nat -A v6br -i ! "$WAN" -p IPv6 --ip6-proto tcp --ip6-dport 53 -j redirect --redirect-target ACCEPT
    fi

    has_jump broute BROUTING v6br || ebtables -t broute -I BROUTING -j v6br
    has_jump filter FORWARD v6br_fw || ebtables -I FORWARD -j v6br_fw
    has_jump filter OUTPUT v6br_out || ebtables -I OUTPUT -j v6br_out
    has_jump filter INPUT v6br_in || ebtables -I INPUT -j v6br_in
    has_jump nat PREROUTING v6br || ebtables -t nat -I PREROUTING -j v6br
}

# Broadcom's flow cache, in its default "L2 & L3" mode, forwards frames between
# two MAC addresses it has already seen without showing them to ebtables. Only
# the first packet a LAN device sends to the gateway would then be filtered or
# redirected; its later DNS queries would slip past. "L3" mode still
# accelerates every connection, but each new one starts in the rules above.
FC=$(which fcctl 2>/dev/null || which fc 2>/dev/null)
flow_mode() { [ -n "$FC" ] && "$FC" status 2>/dev/null | sed -n 's/.*Acceleration Mode: <\(.*\)>.*/\1/p'; }
flow_l3() {
    case "$(flow_mode)" in
        L2*) "$FC" config --accel-mode 0 >/dev/null 2>&1 && logger -t ipv6-bridge "flow cache set to L3 mode" ;;
    esac
}

rules_ok() {
    has_jump broute BROUTING v6br && has_jump filter FORWARD v6br_fw &&
        has_jump filter OUTPUT v6br_out && has_jump filter INPUT v6br_in &&
        [ "$(ebtables -t broute -L v6br 2>/dev/null | grep -c IPv6)" -ge 1 ] &&
        [ "$(ebtables -L v6br_fw 2>/dev/null | grep -c IPv6)" -ge 2 ]
}

ip6_rule() { ip6tables "$@" 2>/dev/null; }
ip6_rules() {
    # The router's own IPv6 now lives on the bridge. With IPv6 disabled in the
    # UI the firmware leaves every ip6tables policy at DROP, output included.
    ip6_rule -C INPUT -i "$BR" -j ACCEPT || ip6_rule -I INPUT 1 -i "$BR" -j ACCEPT
    ip6_rule -C INPUT -i lo -j ACCEPT || ip6_rule -I INPUT 1 -i lo -j ACCEPT
    ip6_rule -C OUTPUT -o "$BR" -j ACCEPT || ip6_rule -I OUTPUT 1 -o "$BR" -j ACCEPT
    ip6_rule -C OUTPUT -o lo -j ACCEPT || ip6_rule -I OUTPUT 1 -o lo -j ACCEPT
    for proto in udp tcp; do
        if [ "$DNS_INTERCEPT" = 1 ]; then
            ip6_rule -t nat -C PREROUTING -i "$BR" -p $proto --dport 53 -j REDIRECT --to-ports 53 ||
                ip6_rule -t nat -A PREROUTING -i "$BR" -p $proto --dport 53 -j REDIRECT --to-ports 53
        else
            while ip6_rule -t nat -D PREROUTING -i "$BR" -p $proto --dport 53 -j REDIRECT --to-ports 53; do :; done
        fi
    done
}

router_v6() {
    # The firmware's helpers assume IPv6 lives on the WAN port; they would only get in the way.
    killall 6relayd odhcp6c 2>/dev/null
    for p in $(ip -6 route show dev "$WAN" 2>/dev/null | awk '!/^fe80/ && !/^ff/ {print $1}'); do
        ip -6 route del "$p" dev "$WAN" 2>/dev/null
    done
    echo 0 > "/proc/sys/net/ipv6/conf/$WAN/accept_ra" 2>/dev/null
    # Let the bridge configure itself from the upstream gateway's advertisements.
    conf accept_ra 2
    conf autoconf 1
    conf disable_ipv6 0
}

solicit() { # restart autoconfiguration so a router solicitation goes out now
    conf disable_ipv6 1
    conf disable_ipv6 0
}

have_v6() { ip -6 route show default dev "$BR" 2>/dev/null | grep -q default; }

start() {
    build_rules
    rules_ok || { echo "ebtables rules are not in place; not bridging"; return 1; }
    flow_l3
    ip6_rules
    router_v6
    if ! in_bridge; then
        brctl addif "$BR" "$WAN" || return 1
        logger -t ipv6-bridge "bridging IPv6 between $WAN and $BR"
    fi
    # The gateway answers a solicitation after a few seconds; ask now, then wait.
    have_v6 || solicit
    i=0
    while [ $i -lt 12 ] && ! have_v6; do sleep 1; i=$((i + 1)); done
    have_v6 || logger -t ipv6-bridge "no IPv6 default route on $BR yet"
}

ensure() {
    if ! rules_ok || ! in_bridge; then
        start
        logger -t ipv6-bridge "bridge or rules restored"
        return
    fi
    flow_l3
    ip6_rules
    [ "$(cat /proc/sys/net/ipv6/conf/$BR/disable_ipv6 2>/dev/null)" = 0 ] || router_v6
    pidof 6relayd >/dev/null 2>&1 && killall 6relayd
    have_v6 || solicit
}

stop() {
    in_bridge && brctl delif "$BR" "$WAN"
    ebtables -t broute -D BROUTING -j v6br 2>/dev/null
    ebtables -D FORWARD -j v6br_fw 2>/dev/null
    ebtables -D OUTPUT -j v6br_out 2>/dev/null
    ebtables -D INPUT -j v6br_in 2>/dev/null
    ebtables -t nat -D PREROUTING -j v6br 2>/dev/null
    ebtables -t broute -X v6br 2>/dev/null
    for c in v6br_fw v6br_out v6br_in; do ebtables -X $c 2>/dev/null; done
    ebtables -t nat -X v6br 2>/dev/null
    for proto in udp tcp; do
        while ip6_rule -t nat -D PREROUTING -i "$BR" -p $proto --dport 53 -j REDIRECT --to-ports 53; do :; done
    done
    [ -n "$FC" ] && "$FC" config --accel-mode 1 >/dev/null 2>&1
    logger -t ipv6-bridge "stopped"
    echo "stopped (IPv6 on the LAN is now whatever the firmware provides)"
}

status() {
    if in_bridge; then echo "bridge:   $WAN is a port of $BR"; else echo "bridge:   $WAN is NOT in $BR"; fi
    if rules_ok; then echo "filters:  in place (only IPv6 crosses)"; else echo "filters:  MISSING"; fi
    echo "dns:      intercept=$DNS_INTERCEPT ($(ebtables -t nat -L v6br 2>/dev/null | grep -c redirect) redirect rules)"
    echo "flows:    flow cache mode $(flow_mode) (must be L3 for the filters to see every connection)"
    echo "router:   $(ip -6 addr show dev "$BR" scope global 2>/dev/null | awk '/inet6/{print $2}' | tr '\n' ' ')"
    echo "route:    $(ip -6 route show default 2>/dev/null | head -1)"
    echo "firmware: ipv6_service=$(nvram get ipv6_service 2>/dev/null)"
    echo "reach:    $(ping6 -c 2 -W 2 -q 2606:4700:4700::1111 2>&1 | tail -1)"
}

case "$1" in
    start) start ;;
    stop) stop ;;
    ensure) ensure ;;
    status) status ;;
    *) echo "usage: $0 start|stop|ensure|status"; exit 1 ;;
esac
