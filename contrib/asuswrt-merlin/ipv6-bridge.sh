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
#        ipv6-bridge.sh hold|release    (called by the service-event hooks)
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
BRMAC=$(cat "/sys/class/net/$BR/address" 2>/dev/null)
# TCP ports of this router that the WAN side must not reach over IPv6.
GUARD_TCP="22 53 80 443 8443"
LOCK=/tmp/ipv6-bridge.lock
# While this file is fresh the firmware is restarting something that wipes
# ebtables, and the WAN port must stay out of the bridge.
HOLD=/tmp/ipv6-bridge.hold
HOLD_MAX=120

held() {
    [ -f "$HOLD" ] || return 1
    [ $(($(date +%s) - $(cat "$HOLD" 2>/dev/null || echo 0))) -lt "$HOLD_MAX" ]
}

conf() { echo "$2" > "/proc/sys/net/ipv6/conf/$BR/$1" 2>/dev/null; }
in_bridge() { [ -d "/sys/class/net/$BR/brif/$WAN" ]; }
has_jump() { ebtables -t "$1" -L "$2" 2>/dev/null | grep -qE -- "-j $3( |\$)"; }
unplug() { in_bridge && brctl delif "$BR" "$WAN"; }

chain() { # chain <table> <name>: create (or empty) a user chain that falls through
    ebtables -t "$1" -N "$2" -P RETURN 2>/dev/null || ebtables -t "$1" -F "$2"
}

# The guard that keeps everything but IPv6 from crossing. It sits in the nat
# table, where one rule on the way in and one on the way out see every frame
# that enters or leaves through the WAN port, forwarded or local.
#
# The firmware empties every ebtables table, this one included, whenever it
# restarts the wireless interfaces or the network, and clients reconnect and
# ask for DHCP at exactly that moment. So the WAN port is only ever in the
# bridge while the guard is in place: the service-event hook unplugs it before
# such a restart (`hold`), and it is plugged back in afterwards (`release`).
build_nat() {
    chain nat v6br
    # Non-IPv6 frames from the WAN port normally never get this far (see
    # build_broute). When they do, they must not enter the bridge.
    ebtables -t nat -A v6br -i "$WAN" -p ! IPv6 -j DROP
    for p in $GUARD_TCP; do
        ebtables -t nat -A v6br -i "$WAN" -d "$BRMAC" -p IPv6 --ip6-proto tcp --ip6-dport "$p" -j DROP
    done
    ebtables -t nat -A v6br -i "$WAN" -d "$BRMAC" -p IPv6 --ip6-proto udp --ip6-dport 53 -j DROP
    if [ "$DNS_INTERCEPT" = 1 ]; then
        # Hand LAN DNS-over-IPv6 frames to this router instead of bridging them on.
        ebtables -t nat -A v6br -i ! "$WAN" -p IPv6 --ip6-proto udp --ip6-dport 53 -j redirect --redirect-target ACCEPT
        ebtables -t nat -A v6br -i ! "$WAN" -p IPv6 --ip6-proto tcp --ip6-dport 53 -j redirect --redirect-target ACCEPT
    fi
    chain nat v6br_post
    # Nothing but IPv6 leaves through the WAN port, forwarded or from this router's bridge.
    ebtables -t nat -A v6br_post -o "$WAN" -p ! IPv6 -j DROP

    has_jump nat PREROUTING v6br || ebtables -t nat -I PREROUTING -j v6br
    has_jump nat POSTROUTING v6br_post || ebtables -t nat -I POSTROUTING -j v6br_post
}

# Non-IPv6 frames arriving on the WAN port are routed, never bridged: this is
# what keeps the router's own IPv4 WAN working while the port is in the
# bridge. Should this rule alone go missing, the guard above drops those
# frames: IPv4 on the WAN pauses, but nothing leaks.
build_broute() {
    chain broute v6br
    ebtables -t broute -A v6br -i "$WAN" -p ! IPv6 -j DROP
    has_jump broute BROUTING v6br || ebtables -t broute -I BROUTING -j v6br
}

nat_ok() {
    redirects=0
    [ "$DNS_INTERCEPT" = 1 ] && redirects=2
    has_jump nat PREROUTING v6br && has_jump nat POSTROUTING v6br_post &&
        ebtables -t nat -L v6br 2>/dev/null | grep -q -- "-p ! IPv6 -i $WAN -j DROP" &&
        ebtables -t nat -L v6br_post 2>/dev/null | grep -q -- "-p ! IPv6 -o $WAN -j DROP" &&
        [ "$(ebtables -t nat -L v6br 2>/dev/null | grep -c redirect)" = "$redirects" ]
}
broute_ok() {
    has_jump broute BROUTING v6br &&
        ebtables -t broute -L v6br 2>/dev/null | grep -q -- "-p ! IPv6 -i $WAN -j DROP"
}
rules_ok() { nat_ok && broute_ok; }

# Earlier versions kept the guard in the filter table.
drop_legacy() {
    ebtables -D FORWARD -j v6br_fw 2>/dev/null
    ebtables -D OUTPUT -j v6br_out 2>/dev/null
    ebtables -D INPUT -j v6br_in 2>/dev/null
    for c in v6br_fw v6br_out v6br_in; do ebtables -X $c 2>/dev/null; done
}

# Put missing rules back. The WAN port is unplugged from the bridge before the
# guard is touched, so there is never a moment with the port in and the guard out.
ensure_rules() {
    if ! nat_ok; then
        unplug && logger -t ipv6-bridge "guard rules missing: WAN port taken out of the bridge"
        build_nat
    fi
    broute_ok || build_broute
    rules_ok
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
    drop_legacy
    if ! ensure_rules; then
        unplug
        echo "ebtables rules are not in place; not bridging"
        return 1
    fi
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
        what=bridge
        nat_ok || what="guard rules"
        nat_ok && ! broute_ok && what="broute rule"
        start
        logger -t ipv6-bridge "$what restored"
        return
    fi
    flow_l3
    ip6_rules
    [ "$(cat /proc/sys/net/ipv6/conf/$BR/disable_ipv6 2>/dev/null)" = 0 ] || router_v6
    pidof 6relayd >/dev/null 2>&1 && killall 6relayd
    have_v6 || solicit
}

stop() {
    unplug
    ebtables -t broute -D BROUTING -j v6br 2>/dev/null
    ebtables -t broute -X v6br 2>/dev/null
    ebtables -t nat -D PREROUTING -j v6br 2>/dev/null
    ebtables -t nat -D POSTROUTING -j v6br_post 2>/dev/null
    ebtables -t nat -X v6br 2>/dev/null
    ebtables -t nat -X v6br_post 2>/dev/null
    drop_legacy
    for proto in udp tcp; do
        while ip6_rule -t nat -D PREROUTING -i "$BR" -p $proto --dport 53 -j REDIRECT --to-ports 53; do :; done
    done
    [ -n "$FC" ] && "$FC" config --accel-mode 1 >/dev/null 2>&1
    logger -t ipv6-bridge "stopped"
    echo "stopped (IPv6 on the LAN is now whatever the firmware provides)"
}

status() {
    if in_bridge; then echo "bridge:   $WAN is a port of $BR"; else echo "bridge:   $WAN is NOT in $BR"; fi
    held && echo "hold:     a firmware restart is in progress; the port stays out until it ends"
    if nat_ok; then echo "guard:    in place (only IPv6 crosses)"; else echo "guard:    MISSING"; fi
    if broute_ok; then echo "broute:   in place (IPv4 on the WAN port is routed)"; else echo "broute:   MISSING (IPv4 on the WAN port is paused)"; fi
    echo "caught:   $(ebtables -t nat -L v6br --Lc 2>/dev/null | sed -n 's/.*-p ! IPv6 -i .* pcnt = \([0-9]*\) .*/\1/p' | head -1) non-IPv6 frames stopped by the guard while the broute rule was missing"
    echo "dns:      intercept=$DNS_INTERCEPT ($(ebtables -t nat -L v6br 2>/dev/null | grep -c redirect) redirect rules)"
    echo "flows:    flow cache mode $(flow_mode) (must be L3 for the rules to see every connection)"
    echo "router:   $(ip -6 addr show dev "$BR" scope global 2>/dev/null | awk '/inet6/{print $2}' | tr '\n' ' ')"
    echo "route:    $(ip -6 route show default 2>/dev/null | head -1)"
    echo "firmware: ipv6_service=$(nvram get ipv6_service 2>/dev/null)"
    echo "reach:    $(ping6 -c 2 -W 2 -q 2606:4700:4700::1111 2>&1 | tail -1)"
}

# One instance at a time: the service loop and the firmware hooks both call in.
lock() {
    i=0
    while ! mkdir "$LOCK" 2>/dev/null; do
        i=$((i + 1))
        [ $i -gt 30 ] && rmdir "$LOCK" 2>/dev/null
        sleep 1
    done
    trap 'rmdir "$LOCK" 2>/dev/null' EXIT
}

case "$1" in
    start)
        lock
        if held; then unplug; else start; fi
        ;;
    ensure)
        lock
        if held; then unplug; else ensure; fi
        ;;
    stop)
        lock
        rm -f "$HOLD"
        stop
        ;;
    hold)
        lock
        date +%s > "$HOLD"
        unplug && logger -t ipv6-bridge "WAN port unplugged while the firmware restarts ($2)"
        ;;
    release)
        lock
        rm -f "$HOLD"
        ensure
        ;;
    status) status ;;
    *) echo "usage: $0 start|stop|ensure|status"; exit 1 ;;
esac
