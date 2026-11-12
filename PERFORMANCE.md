# Data path and performance notes

This fork reworks the tunnel data path so that a small router can carry a
fast line. The protocol side (registration, handshake, CONNECT-IP) is unchanged.
A guided tour of the code, in Chinese, is in `docs/GUIDE.zh-CN.md`.

## Results

Measured on an ASUS RT-AX86U (Broadcom BCM4908, 4 x Cortex-A53 class cores at
1.8 GHz, Linux 4.1.52, Asuswrt-Merlin 388.12) behind a 5G fixed-wireless line.
The outer connection uses IPv6; the tunnel carries IPv4 with an MTU of 1280.
Downloads are HTTP from a public speed-test server, run on the router itself
and bound to the tunnel address.

| Client | 8 flows | 1 flow | Upload |
|---|---|---|---|
| usque (Go) 4.2.1, `nativetun` | 54 Mbit/s (4 flows) | 50-69 Mbit/s | not measured |
| usque-rs 0.1.0 | 140-200 Mbit/s (4 flows) | 130-155 Mbit/s | not measured |
| this fork | 590-650 Mbit/s | 410-435 Mbit/s | 78-138 Mbit/s |
| official client on a desktop PC, same line, same hours | - | 330-435 Mbit/s | 19-64 Mbit/s |

In steady state the router receives about 77,000 tunnelled packets per second
(roughly 750 Mbit/s); a gigabit WAN port tops out near 87,000 packets of this
size. The QUIC thread is then the busiest stage, at 11-13 us of CPU per packet.

Forwarded traffic, which is what a LAN device actually gets, was measured from
a Windows PC on the router's Wi-Fi, NATed into the tunnel, with merged segments
enabled: 250-330 Mbit/s for a single download and 511 Mbit/s for six in
parallel. Native IPv6 from the same PC, which bypasses the tunnel, reached
180-250 Mbit/s for a single download in the same hours. While the six
downloads ran, 77 of 78 pings sent through the tunnel were answered (94 ms on
average, 207 ms at worst), which is what the service's fallback check relies
on. The table above is the
upper bound the router itself can carry. The same results held after an
upgrade to firmware 388.13.

## What changed

### Three-stage pipeline

The original loop did everything in one task, so one core was the ceiling.
The data path now uses plain threads and blocking system calls:

- the **QUIC thread** owns the connection: it receives UDP with `recvmmsg`,
  runs quiche, and sends with `sendmmsg`;
- **tun-tx** writes decrypted packets to the TUN device, so the kernel's IP
  stack work for the downlink runs on another core;
- **tun-rx** reads packets from the TUN device.

Packets travel between threads in fixed-size batches (64 packets) that are
recycled through return channels, so the steady state allocates nothing
outside quiche. The queues apply backpressure instead of dropping: when the
QUIC thread falls behind, tun-rx blocks and packets wait in the TUN queue; when
tun-tx falls behind, UDP waits in the socket buffer.

On machines with four or more CPUs the QUIC thread is pinned to CPU 2 and the
TUN threads to CPU 3. Without pinning the scheduler tends to stack the stages
on one core (each wake-up pulls the next stage onto the waker's CPU), which
cost about a quarter of the throughput here.

### Merging TCP segments on TUN writes

The TUN device is opened with `IFF_VNET_HDR`. Before writing, tun-tx merges
consecutive TCP segments of the same flow into one large packet with a
`virtio_net_hdr` that tells the kernel how to cut it up again (`src/gro.rs`).
The kernel then runs its receive path once per merged packet instead of once
per segment. On this router that took single-flow throughput from about 200 to
about 430 Mbit/s and cut tun-tx's CPU use by more than half; a typical write
carries 7-15 segments.

The merge rules follow the kernel's own GRO: same flow, consecutive sequence
numbers, identical headers apart from the fields segmentation regenerates, a
short or PSH segment only at the end. Each segment's TCP checksum is verified
first, because the kernel recomputes checksums when it segments and would
otherwise turn a corrupt segment into a valid-looking one. The unit tests
segment every merged packet again and compare the result byte for byte with
the packets that went in.

Only IPv4 TCP is merged. TUN offloads towards userspace are left off, so
packets read from the device are unchanged.

### Buffers and queues

- The UDP socket asks for 8 MiB buffers (`SO_RCVBUFFORCE`/`SO_SNDBUFFORCE`).
  With the 512 KiB default about 0.4 % of datagrams were dropped at the socket.
- The TUN transmit queue is lengthened to 5000 packets.
- The QUIC DATAGRAM send queue is capped at 1024 packets. Packets wait there
  when the congestion window is full, so the cap bounds the delay the tunnel
  can add; with a deep queue and a stalled congestion controller, latency
  through the tunnel reached several seconds.

### Congestion control

The tunnel's own packets default to BBR2. With CUBIC, uploads sat at 38 Mbit/s
on a line that carries 145 Mbit/s directly, without any loss being reported;
BBR2 reached 78-138 Mbit/s with 15-25 ms of added latency under load. BBR
(v1) was fast but occasionally collapsed to a few Mbit/s.

### Long-running behaviour

- A keepalive (`--keepalive-period`, default 30 s) is now actually sent when
  the tunnel is idle, and the QUIC idle timeout is set to two periods plus 5 s.
  A dead peer or a changed path therefore ends the session, and the next
  packet from the TUN device opens a new one.
- The proxy can stop forwarding a tunnel while it keeps acknowledging at the
  QUIC level, which neither the idle timeout nor the keepalive notices. This
  was seen when a WARP client on the LAN ran its own tunnel inside this one:
  pings went out, 44-byte acknowledgements came back, and nothing else. The
  session now ends when the proxy closes or resets the CONNECT-IP stream, sends
  GOAWAY, or when 32 or more packets have gone out and nothing has come back
  for 12 s; the next packet from the TUN device opens a new session.
- A session that fails within 2 s is followed by a 1 s pause, so an unreachable
  endpoint does not turn into a busy loop.
- The one-line live statistics are printed only when stderr is a terminal.
  Redirected to a file they would add a line per second for ever.
- Memory is bounded: batches are pooled, the inter-thread queues hold at most
  128 batches each, and the QUIC queues are capped. Resident memory was
  14-30 MiB in the tests above.

## Environment variables

| Variable | Effect |
|---|---|
| `USQUE_PIN=quic,tunrx,tx0[,tx1...]` | CPUs for the QUIC thread, tun-rx, and one tun-tx thread per extra entry. `off` disables pinning. |
| `USQUE_CC=reno\|cubic\|bbr\|bbr2` | Congestion controller (default `bbr2`). |
| `USQUE_GRO=0` | Do not merge TCP segments on TUN writes. |
| `USQUE_VNET_HDR=0` | Open the TUN device without `IFF_VNET_HDR` (implies no merging). |
| `USQUE_STATS=1` / `0` | Force the live statistics line on or off. |
| `USQUE_SEQDIAG=1` | Debug aid: every 5 s print QUIC path statistics and, from the downlink TCP sequence numbers, how many inner packets went missing before reaching this client. |

## Platform notes: Broadcom routers

On the RT-AX86U, packets that are not hardware-forwarded reach the CPU through
a 512-packet ring that the `bcmsw_rx` kernel thread drains. At tunnel speeds
the ring overflowed whenever that thread had to wait for a CPU: 2-6 % of the
tunnel's packets were lost before Linux ever counted them (the drops show up
only in `bs /b/e cpu/index=host rxq_stat`). `USQUE_SEQDIAG=1` is what made
this visible. Two settings fixed it:

- pin `bcmsw_rx` to CPU 0 and give it a real-time priority;
- enable RPS on the WAN interface towards CPU 1 with a deeper backlog, so that
  thread only moves packets off the ring and the IP/UDP work happens elsewhere.

`contrib/asuswrt-merlin/` has a service script that applies both, starts the
tunnel, and routes the LAN's IPv4 through it.

## Ideas not pursued

- Moving `recvmmsg` to a fourth thread would take the kernel copy off the QUIC
  thread, worth perhaps 15 % of headroom.
- A second connection (second registration) with flows hashed across the two
  would double the QUIC capacity.
- A faster allocator (mimalloc) made no measurable difference to the per-packet
  cost.
