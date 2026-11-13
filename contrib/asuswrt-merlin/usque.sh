#!/bin/sh
# usque-rs as a LAN-wide IPv4 exit on Asuswrt-Merlin (written for the RT-AX86U).
#
# All IPv4 traffic from the LAN is routed into the MASQUE tunnel; IPv6 and the
# router's own traffic keep using the WAN directly. The LAN is only routed
# into the tunnel while a probe through it is answered: right after boot, or
# whenever the tunnel is down, LAN traffic uses the WAN directly instead of
# disappearing into a dead tunnel.
#
# usage: usque.sh start|stop|restart|status|fw|rotate
#
# Files (all in $DIR):
#   usque-rs      the binary
#   config.json   created by `usque-rs register`
#   env           optional overrides, one VAR=value per line, e.g.
#                   ROUTE_LAN=0      keep the tunnel up but do not route the LAN into it
#                   FALLBACK=0       keep the LAN routed into the tunnel even when it is down
#                   USQUE_GRO=0      disable TCP segment merging on TUN writes
#                   USQUE_PIN=off    disable thread pinning

DIR=/jffs/usque
IF=warp0
TABLE=211
PRIO=9000
MTU=1280
SNI=zt-masque.cloudflareclient.com
LOG=/tmp/usque.log
PID=/var/run/usque-supervisor.pid
CHILD=/var/run/usque.pid
# Cloudflare's WARP ingress ranges (consumer, WireGuard, MASQUE, MASQUE over
# HTTP/2). A WARP client on the LAN must reach these outside our tunnel:
# running one WARP tunnel inside another makes Cloudflare stop forwarding for
# the outer one. Cloudflare documents the same exclusion for its own WAN
# on-ramps ("double encapsulation").
WARP_INGRESS="162.159.192.0/24 162.159.193.0/24 162.159.197.0/24 162.159.198.0/24"
# Addresses pinged through the tunnel to see whether it carries traffic, how
# often (seconds), and how many checks in a row must fail, or succeed, before
# the LAN is switched to the WAN, or back.
PROBE="1.1.1.1 8.8.8.8"
CHECK=5
FAILS=2
PASSES=2

ROUTE_LAN=1
FALLBACK=1
RUST_LOG=info
if [ -f "$DIR/env" ]; then
    set -a
    . "$DIR/env"
    set +a
fi
export RUST_LOG

LAN_IF=$(nvram get lan_ifname 2>/dev/null); LAN_IF=${LAN_IF:-br0}
WAN_IF=$(nvram get wan0_ifname 2>/dev/null); WAN_IF=${WAN_IF:-eth0}

lan_net() { ip -4 route show dev "$LAN_IF" scope link | awk 'NR==1{print $1}'; }
tun_ip() { ip -4 addr show dev "$IF" 2>/dev/null | awk '/inet /{sub(/\/.*/, "", $2); print $2; exit}'; }
have_if() { ip link show "$IF" >/dev/null 2>&1; }

# --- system tuning -----------------------------------------------------------
# Packets that are not hardware-forwarded reach the CPU through a 512-packet
# ring drained by the bcmsw_rx kernel thread. At tunnel speeds that ring
# overflows within milliseconds whenever the thread has to wait for a CPU, and
# the drops are invisible to Linux counters. So: give the thread CPU 0 and a
# real-time priority, and let CPU 1 do the IP/UDP receive work (RPS), with a
# deeper backlog to absorb bursts. usque-rs itself uses CPUs 2 and 3.
tune() {
    modprobe tun 2>/dev/null
    p=$(pidof bcmsw_rx 2>/dev/null)
    if [ -n "$p" ]; then
        taskset -p 1 "$p" >/dev/null 2>&1
        chrt -f -p 5 "$p" >/dev/null 2>&1
    fi
    [ -w "/sys/class/net/$WAN_IF/queues/rx-0/rps_cpus" ] && echo 2 > "/sys/class/net/$WAN_IF/queues/rx-0/rps_cpus"
    echo 8192 > /proc/sys/net/core/netdev_max_backlog
}

untune() {
    p=$(pidof bcmsw_rx 2>/dev/null)
    if [ -n "$p" ]; then
        chrt -o -p 0 "$p" >/dev/null 2>&1
        taskset -p f "$p" >/dev/null 2>&1
    fi
    [ -w "/sys/class/net/$WAN_IF/queues/rx-0/rps_cpus" ] && echo 0 > "/sys/class/net/$WAN_IF/queues/rx-0/rps_cpus"
    echo 1000 > /proc/sys/net/core/netdev_max_backlog
}

# --- firewall ----------------------------------------------------------------
# Each adds its rule only if it is missing, and notes in FW_CHANGED that it had to.
ipt_add() { t=$1; c=$2; shift 2; iptables -t "$t" -C "$c" "$@" 2>/dev/null || { iptables -t "$t" -A "$c" "$@"; FW_CHANGED=1; }; }
ipt_ins() { t=$1; c=$2; shift 2; iptables -t "$t" -C "$c" "$@" 2>/dev/null || { iptables -t "$t" -I "$c" 1 "$@"; FW_CHANGED=1; }; }
ipt_del() { t=$1; c=$2; shift 2; while iptables -t "$t" -D "$c" "$@" 2>/dev/null; do :; done; }

fw_rules() { # fw_rules <ipt_add|ipt_del> <ipt_ins|ipt_del>
    mss=$((MTU - 40))
    $1 nat POSTROUTING -o "$IF" -j MASQUERADE
    $1 mangle FORWARD -o "$IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$mss"
    $1 mangle FORWARD -i "$IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$mss"
    # Nothing on the far side of the tunnel may open connections to the router.
    $2 filter INPUT -i "$IF" -m state --state NEW -j DROP
}
fw_up() { have_if && fw_rules ipt_add ipt_ins; }
fw_down() { fw_rules ipt_del ipt_del; }

# --- routing -----------------------------------------------------------------
rule_del() { for p in "$@"; do while ip rule del prio "$p" 2>/dev/null; do :; done; done; }
lan_routed() { ip rule list | grep -q "^$PRIO:"; }
# The rules at the given priorities, one per line with single spaces, as
# `ip rule list` words them: "9000: from 192.168.50.0/24 lookup 211".
rules_at() {
    ip rule list | awk -v a="$1:" -v b="${2:-$1}:" '$1 == a || $1 == b { $1 = $1; print }'
}

# The tunnel's own table, and a rule for connections bound to the tunnel
# address (`curl --interface`, the probe below). Present whenever the
# interface exists; on its own it moves no LAN traffic.
route_base() {
    have_if || return 1
    ip route replace default dev "$IF" table "$TABLE"
    rule_del $((PRIO - 20))
    a=$(tun_ip)
    [ -n "$a" ] && ip rule add from "$a" lookup "$TABLE" prio $((PRIO - 20))
    ip route flush cache
}

# True if the table still has its route and the tunnel address has exactly its one rule.
route_ok() {
    ip route show table "$TABLE" 2>/dev/null | grep -q "^default dev $IF" || return 1
    a=$(tun_ip)
    [ -z "$a" ] || [ "$(rules_at $((PRIO - 20)))" = "$((PRIO - 20)): from $a lookup $TABLE" ]
}

# Connections set up along the other path cannot continue on this one. Forget
# them, in the kernel and in the hardware flow cache, so that they fail at
# once and are opened again instead of hanging.
flow_reset() {
    conntrack -F >/dev/null 2>&1
    fc flush >/dev/null 2>&1
    ip route flush cache
}

# The rules that send the LAN ($1) into the tunnel, worded as rules_at prints them.
# Private and link-local destinations, and the WARP ingress, stay on the main table.
lan_rules() {
    for d in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10 224.0.0.0/4 $WARP_INGRESS; do
        echo "$((PRIO - 10)): from $1 to $d lookup main"
    done
    echo "$PRIO: from $1 lookup $TABLE"
}

# True if exactly those rules are in place: none missing, none left over.
lan_ok() {
    net=$(lan_net)
    [ -n "$net" ] || return 0
    [ "$(lan_rules "$net" | sort)" = "$(rules_at $((PRIO - 10)) "$PRIO" | sort)" ]
}

# Send the LAN's IPv4 into the tunnel.
lan_on() {
    net=$(lan_net)
    [ "$ROUTE_LAN" = 1 ] && [ -n "$net" ] || return 0
    rule_del $((PRIO - 10)) "$PRIO"
    lan_rules "$net" | while read -r prio rule; do
        # shellcheck disable=SC2086  # the rule is a list of words
        ip rule add $rule prio "${prio%:}"
    done
    flow_reset
}

# Let the LAN's IPv4 use the WAN directly.
lan_off() {
    rule_del $((PRIO - 10)) "$PRIO"
    flow_reset
}

route_down() {
    rule_del $((PRIO - 20)) $((PRIO - 10)) "$PRIO"
    ip route flush table "$TABLE" 2>/dev/null
    ip route flush cache
}

# True if a ping sent through the tunnel is answered. The ping also wakes the
# tunnel up: usque-rs connects when the first packet arrives.
tunnel_ok() {
    a=$(tun_ip)
    [ -n "$a" ] || return 1
    for t in $PROBE; do
        ping -c 1 -W 2 -I "$a" "$t" >/dev/null 2>&1 && return 0
    done
    return 1
}

# --- log ---------------------------------------------------------------------
rotate() {
    [ -f "$LOG" ] || return 0
    if [ "$(wc -c < "$LOG")" -gt 524288 ]; then
        tail -c 65536 "$LOG" > "$LOG.1"
        : > "$LOG"
    fi
}

# --- supervisor --------------------------------------------------------------
alive() { [ -f "$1" ] && kill -0 "$(cat "$1")" 2>/dev/null; }

# Re-apply routing and firewall entries that have gone missing.
# $1 is where the LAN should be going right now: on (tunnel) or off (WAN).
#
# Every entry is checked, not one that stands for the rest: the firmware can
# drop a single rule or one firewall table and leave the others.
ensure() {
    # Optional companion: native IPv6 for the LAN by bridging it to the WAN.
    [ -x "$DIR/ipv6-bridge.sh" ] && "$DIR/ipv6-bridge.sh" ensure
    have_if || return 0
    fixed=
    if ! route_ok; then
        route_base
        fixed="$fixed tunnel-route"
    fi
    # While LAN rules were missing, connections went out the wrong way;
    # lan_on rebuilds the whole set and resets those connections.
    if [ "$1" = on ] && [ "$ROUTE_LAN" = 1 ] && ! lan_ok; then
        lan_on
        fixed="$fixed lan-rules"
    fi
    FW_CHANGED=
    fw_up
    [ -z "$FW_CHANGED" ] || fixed="$fixed firewall"
    [ -z "$fixed" ] || logger -t usque "restored:$fixed"
}

# Watch the tunnel while usque-rs runs, and point the LAN at it only while it
# carries traffic.
watch() {
    lan=off
    bad=0
    good=0
    # Start from a clean slate: no LAN rules until the tunnel has proved itself.
    rule_del $((PRIO - 10)) "$PRIO"
    [ "$FALLBACK" = 1 ] || { lan=on; lan_on; }
    while alive "$CHILD"; do
        if tunnel_ok; then
            bad=0
            good=$((good + 1))
            if [ $lan = off ] && [ $good -ge "$PASSES" ]; then
                lan=on
                lan_on
                logger -t usque "tunnel carries traffic: LAN IPv4 goes through it"
            fi
        else
            good=0
            bad=$((bad + 1))
            if [ $lan = on ] && [ "$FALLBACK" = 1 ] && [ $bad -ge "$FAILS" ]; then
                lan=off
                lan_off
                logger -t usque "tunnel carries no traffic: LAN IPv4 uses the WAN until it does"
            fi
        fi
        # The firmware resets routing rules and firewall tables whenever the
        # WAN comes up or the firewall is rebuilt; put ours back when missing.
        ensure $lan
        # (`sleep & wait` keeps the shell responsive to the stop signal and
        # reaps usque-rs when it exits.)
        sleep "$CHECK" &
        wait $!
    done
}

run() {
    echo $$ > "$PID"
    trap 'alive "$CHILD" && kill "$(cat "$CHILD")"; route_down; fw_down; rm -f "$PID" "$CHILD"; exit 0' TERM INT
    while :; do
        tune
        rotate
        # The tunnel connects over IPv6, so bring that up first if we manage it.
        [ -x "$DIR/ipv6-bridge.sh" ] && "$DIR/ipv6-bridge.sh" start
        "$DIR/usque-rs" -c "$DIR/config.json" nativetun -6 -s "$SNI" -n "$IF" -S -m "$MTU" >> "$LOG" 2>&1 &
        echo $! > "$CHILD"
        i=0
        while [ $i -lt 20 ] && ! have_if; do sleep 1; i=$((i + 1)); done
        if have_if; then
            fw_up
            route_base
            logger -t usque "tunnel interface $IF is up"
        else
            logger -t usque "tunnel interface $IF did not appear"
        fi
        watch
        logger -t usque "usque-rs exited; restarting in 5 s"
        route_down
        sleep 5
    done
}

start() {
    if alive "$PID"; then
        echo "already running"
        return 0
    fi
    [ -x "$DIR/usque-rs" ] && [ -f "$DIR/config.json" ] || { echo "missing $DIR/usque-rs or config.json"; return 1; }
    nohup "$0" run >/dev/null 2>&1 &
    cru a usque_rotate "13 4 * * * $0 rotate" 2>/dev/null
    echo "started"
}

stop() {
    cru d usque_rotate 2>/dev/null
    if alive "$PID"; then
        kill "$(cat "$PID")"
        i=0
        while [ $i -lt 10 ] && alive "$PID"; do sleep 1; i=$((i + 1)); done
    fi
    alive "$CHILD" && kill "$(cat "$CHILD")"
    route_down
    fw_down
    untune
    rm -f "$PID" "$CHILD"
    echo "stopped"
}

status() {
    if alive "$PID"; then echo "supervisor: running (pid $(cat "$PID"))"; else echo "supervisor: not running"; fi
    if alive "$CHILD"; then echo "usque-rs:   running (pid $(cat "$CHILD"))"; else echo "usque-rs:   not running"; fi
    if have_if; then
        echo "interface:  $IF $(tun_ip) mtu $(cat "/sys/class/net/$IF/mtu")"
        if lan_routed; then
            echo "lan:        IPv4 goes through the tunnel"
        elif [ "$ROUTE_LAN" != 1 ]; then
            echo "lan:        IPv4 uses the WAN (ROUTE_LAN=0)"
        else
            echo "lan:        IPv4 uses the WAN: the tunnel is not carrying traffic"
        fi
        echo "rules:"
        ip rule list | grep -E "lookup ($TABLE|main) *$" | grep -vE '^32766' | sed 's/^/  /'
        echo "exit:       $(curl -4 -s --max-time 8 --interface "$IF" https://cloudflare.com/cdn-cgi/trace | grep -E '^(ip|colo|warp)=' | tr '\n' ' ')"
    else
        echo "interface:  $IF is down (LAN traffic uses the WAN directly)"
    fi
}

case "$1" in
    start) start ;;
    stop) stop ;;
    restart) stop; start ;;
    status) status ;;
    fw) fw_up ;;
    rotate) rotate ;;
    run) run ;;
    *) echo "usage: $0 start|stop|restart|status|fw|rotate"; exit 1 ;;
esac
