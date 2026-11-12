#!/bin/sh
# Optional helper for Asuswrt-Merlin's "IPv6 Passthrough" mode.
#
# In that mode the firmware relays every Router Advertisement heard on the WAN
# to the LAN, rewriting the source to the router's own address. If anything
# else on the WAN segment sends RAs with a router lifetime of 0 (Thread border
# routers such as HomePods and Apple TVs do, to announce a route), LAN clients
# see "this router" withdraw itself right after announcing itself and end up
# with IPv6 addresses but no default route.
#
# Dropping zero-lifetime RAs on the WAN keeps the relay to the real gateway's.
# Run from /jffs/scripts/firewall-start (the rule is lost whenever the firewall
# is rebuilt).
WAN_IF=$(nvram get wan0_ifname 2>/dev/null); WAN_IF=${WAN_IF:-eth0}
# Bytes 46-47 of the packet are the RA's router lifetime.
set -- INPUT -i "$WAN_IF" -p ipv6-icmp --icmpv6-type 134 -m u32 --u32 "44&0xFFFF=0" -j DROP
ip6tables -C "$@" 2>/dev/null || ip6tables -I "$@"
