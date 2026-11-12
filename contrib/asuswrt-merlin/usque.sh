#!/bin/sh
# usque-rs as a LAN-wide IPv4 exit on Asuswrt-Merlin (written for the RT-AX86U).
#
# All IPv4 traffic from the LAN is routed into the MASQUE tunnel; IPv6 and the
# router's own traffic keep using the WAN directly. If the tunnel process is
# not running, its route disappears and LAN traffic falls back to the WAN.
#
# usage: usque.sh start|stop|restart|status|fw|rotate
#
# Files (all in $DIR):
#   usque-rs      the binary
#   config.json   created by `usque-rs register`
#   env           optional overrides, one VAR=value per line, e.g.
#                   ROUTE_LAN=0      keep the tunnel up but do not route the LAN into it
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

ROUTE_LAN=1
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
ipt_add() { t=$1; c=$2; shift 2; iptables -t "$t" -C "$c" "$@" 2>/dev/null || iptables -t "$t" -A "$c" "$@"; }
ipt_ins() { t=$1; c=$2; shift 2; iptables -t "$t" -C "$c" "$@" 2>/dev/null || iptables -t "$t" -I "$c" 1 "$@"; }
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
rule_flush() {
    for p in $((PRIO - 20)) $((PRIO - 10)) "$PRIO"; do
        while ip rule del prio "$p" 2>/dev/null; do :; done
    done
}

# Compare selectors, not just priority: another owned rule can survive a
# partial firmware reset while the LAN rule or one exclusion is missing.
rule_has() {
    ip rule list | awk -v prio="$1:" -v src="$2" -v dst="$3" -v table="$4" '
        function norm(s) { sub("/32$", "", s); return s }
        $1 == prio {
            from = "all"; to = "all"; lookup = ""
            for (i = 2; i < NF; i++) {
                if ($i == "from") from = $(i + 1)
                if ($i == "to") to = $(i + 1)
                if ($i == "lookup") lookup = $(i + 1)
            }
            if (norm(from) == norm(src) && norm(to) == norm(dst) && lookup == table) found = 1
        }
        END { exit !found }
    '
}

rule_ensure() {
    if ! rule_has "$1" "$2" "$3" "$4"; then
        ip rule add from "$2" to "$3" lookup "$4" prio "$1" || return 1
        ROUTE_CHANGED=1
    fi
}

route_up() {
    have_if || return 1
    ROUTE_CHANGED=0
    if ! ip route show table "$TABLE" 2>/dev/null | awk -v dev="$IF" '
        $1 == "default" { for (i = 2; i < NF; i++) if ($i == "dev" && $(i + 1) == dev) found = 1 }
        END { exit !found }
    '; then
        ip route replace default dev "$IF" table "$TABLE" || return 1
        ROUTE_CHANGED=1
    fi
    a=$(tun_ip)
    [ -z "$a" ] || rule_ensure $((PRIO - 20)) "$a" all "$TABLE" || return 1
    net=$(lan_net)
    if [ "$ROUTE_LAN" = 1 ] && [ -n "$net" ]; then
        for d in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10 224.0.0.0/4 $WARP_INGRESS; do
            rule_ensure $((PRIO - 10)) "$net" "$d" main || return 1
        done
        rule_ensure "$PRIO" "$net" all "$TABLE" || return 1
    fi
    if [ "$ROUTE_CHANGED" = 1 ]; then
        ip route flush cache
        logger -t usque "routing rules restored"
    fi
}

route_down() {
    rule_flush
    ip route flush table "$TABLE" 2>/dev/null
    ip route flush cache
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
ensure() {
    # Optional companion: native IPv6 for the LAN by bridging it to the WAN.
    [ -x "$DIR/ipv6-bridge.sh" ] && "$DIR/ipv6-bridge.sh" ensure
    have_if || return 0
    route_up
    # Check every owned NAT, MSS and INPUT rule, even if NAT survived.
    fw_up
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
            route_up
            logger -t usque "tunnel interface $IF is up"
        else
            logger -t usque "tunnel interface $IF did not appear"
        fi
        # The firmware resets routing rules and firewall tables whenever the
        # WAN comes up or the firewall is rebuilt; put ours back when missing.
        # (`sleep & wait` keeps the shell responsive to the stop signal and
        # reaps usque-rs when it exits.)
        while alive "$CHILD"; do
            sleep 15 &
            wait $!
            ensure
        done
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
