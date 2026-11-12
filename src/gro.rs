//! Userspace TCP receive coalescing for TUN writes.
//!
//! Writing one IP packet per `write()` makes the kernel run its whole receive
//! path (routing, netfilter, TCP or forwarding) once per packet. With a TUN
//! device opened with `IFF_VNET_HDR`, consecutive TCP segments of one flow can
//! instead be handed over as a single large packet plus a `virtio_net_hdr`
//! describing how to cut it back into segments. This is the same idea as
//! kernel GRO, and the rules below mirror `tcp_gro_receive`: a merged packet,
//! once segmented again, is byte-for-byte what was received.
//!
//! Only IPv4 TCP data segments are merged; everything else passes through.

/// Size of the legacy `struct virtio_net_hdr` that prefixes every TUN packet.
pub const VNET_HDR_LEN: usize = 10;
/// Upper bound on packets merged into one write (also the batch size).
pub const MAX_SEGS: usize = 64;
/// Room for the virtio header plus the largest IPv4 + TCP header.
pub const MERGED_HDR_MAX: usize = VNET_HDR_LEN + IPV4_HLEN + 60;

const MAX_GROUPS: usize = 16;
/// Keep merged packets well below the 64 KiB IP limit and the TUN frag limit.
const MAX_MERGED_LEN: usize = 60_000;
const IPV4_HLEN: usize = 20;
const TCP_FLAG_PSH: u8 = 0x08;
const TCP_FLAG_ACK: u8 = 0x10;
const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;
const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;

/// Ones-complement sum of `data` as big-endian 16-bit words, unfolded.
fn sum_bytes(data: &[u8], mut sum: u64) -> u64 {
    let mut chunks = data.chunks_exact(4);
    for c in &mut chunks {
        sum += u64::from(u32::from_be_bytes([c[0], c[1], c[2], c[3]]));
    }
    let rest = chunks.remainder();
    if rest.len() >= 2 {
        sum += u64::from(u16::from_be_bytes([rest[0], rest[1]]));
    }
    if rest.len() % 2 == 1 {
        sum += u64::from(rest[rest.len() - 1]) << 8;
    }
    sum
}

const fn fold(mut sum: u64) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

/// Unfolded TCP pseudo-header sum for an IPv4 packet with `tcp_len` bytes of TCP.
fn pseudo_sum(ip: &[u8], tcp_len: usize) -> u64 {
    sum_bytes(&ip[12..20], 6 + tcp_len as u64)
}

/// A group of consecutive segments of one flow that will be written as one packet.
#[derive(Clone, Copy)]
pub struct Group {
    /// Batch indexes of the member packets, in sequence order.
    members: [u8; MAX_SEGS],
    n: u8,
    /// TCP payload size of every member but possibly the last.
    gso_size: u16,
    /// IP total length of the merged packet.
    total_len: u32,
    next_seq: u32,
    closed: bool,
}

impl Group {
    pub fn members(&self) -> &[u8] {
        &self.members[..self.n as usize]
    }
}

/// One write to the TUN device.
#[derive(Clone, Copy)]
pub enum Op {
    /// Write packet `i` of the batch unchanged.
    Single(u8),
    /// Write the members of the group as one merged packet.
    Merged(Group),
}

struct Seg {
    thl: usize,
    payload: usize,
    seq: u32,
    psh: bool,
}

/// Parse `pkt` as a mergeable IPv4 TCP data segment with a valid checksum.
fn parse(pkt: &[u8]) -> Option<Seg> {
    // IPv4 without options, TCP, DF set, not a fragment.
    if pkt.len() < IPV4_HLEN + 20 || pkt[0] != 0x45 || pkt[9] != 6 {
        return None;
    }
    if usize::from(u16::from_be_bytes([pkt[2], pkt[3]])) != pkt.len() {
        return None;
    }
    if u16::from_be_bytes([pkt[6], pkt[7]]) != 0x4000 {
        return None;
    }
    let tcp = &pkt[IPV4_HLEN..];
    let thl = usize::from(tcp[12] >> 4) * 4;
    if thl < 20 || tcp.len() <= thl || tcp[12] & 0x0f != 0 {
        return None;
    }
    // Only plain data segments: ACK set, optionally PSH, nothing else.
    let flags = tcp[13];
    if flags & !(TCP_FLAG_ACK | TCP_FLAG_PSH) != 0 || flags & TCP_FLAG_ACK == 0 {
        return None;
    }
    // The kernel recomputes checksums when it segments a merged packet, so a
    // corrupt segment must never be merged: verify what the sender wrote.
    if fold(sum_bytes(tcp, pseudo_sum(pkt, tcp.len()))) != 0xffff {
        return None;
    }
    Some(Seg {
        thl,
        payload: tcp.len() - thl,
        seq: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
        psh: flags & TCP_FLAG_PSH != 0,
    })
}

/// True if both packets belong to the same TCP flow.
fn same_flow(a: &[u8], b: &[u8]) -> bool {
    a[12..24] == b[12..24]
}

/// True if `pkt` may follow `head` in a merged packet (same flow assumed):
/// every header field the segmenter will not regenerate must be identical.
fn headers_match(head: &[u8], pkt: &[u8], thl: usize) -> bool {
    let (ht, pt) = (&head[IPV4_HLEN..], &pkt[IPV4_HLEN..]);
    // IP: version/IHL, TOS, flags/fragment, TTL, protocol.
    head[..2] == pkt[..2]
        && head[6..10] == pkt[6..10]
        // TCP: ack number, data offset, flags except PSH, window, urgent, options.
        && ht[8..13] == pt[8..13]
        && (ht[13] ^ pt[13]) & !TCP_FLAG_PSH == 0
        && ht[14..16] == pt[14..16]
        && ht[18..thl] == pt[18..thl]
}

/// Plans the TUN writes for a batch of packets. Reused across batches; never
/// allocates after construction.
pub struct Gro {
    open: Vec<Group>,
    ops: Vec<Op>,
}

impl Gro {
    pub fn new() -> Self {
        Self {
            open: Vec::with_capacity(MAX_GROUPS),
            ops: Vec::with_capacity(MAX_SEGS),
        }
    }

    fn emit(ops: &mut Vec<Op>, g: Group) {
        if g.n == 1 {
            ops.push(Op::Single(g.members[0]));
        } else {
            ops.push(Op::Merged(g));
        }
    }

    /// Decide how to write packets `0..n` (`n <= MAX_SEGS`), where `pkt(i)` is
    /// the IP packet at batch index `i`. The order of packets within a flow is
    /// preserved.
    pub fn plan<'a>(&mut self, n: usize, pkt: impl Fn(usize) -> &'a [u8]) -> &[Op] {
        debug_assert!(n <= MAX_SEGS);
        self.open.clear();
        self.ops.clear();
        for i in 0..n.min(MAX_SEGS) {
            let p = pkt(i);
            let slot = if p.len() >= IPV4_HLEN + 20 && p[0] == 0x45 {
                self.open
                    .iter()
                    .position(|g| same_flow(pkt(usize::from(g.members[0])), p))
            } else {
                None
            };
            let seg = parse(p);

            // Try to extend the flow's open group.
            if let (Some(s), Some(seg)) = (slot, seg.as_ref()) {
                let g = &mut self.open[s];
                let head = pkt(usize::from(g.members[0]));
                let head_thl = usize::from(head[IPV4_HLEN + 12] >> 4) * 4;
                if !g.closed
                    && seg.seq == g.next_seq
                    && seg.thl == head_thl
                    && seg.payload <= usize::from(g.gso_size)
                    && (g.n as usize) < MAX_SEGS
                    && g.total_len as usize + seg.payload <= MAX_MERGED_LEN
                    && headers_match(head, p, head_thl)
                {
                    g.members[g.n as usize] = i as u8;
                    g.n += 1;
                    g.total_len += seg.payload as u32;
                    g.next_seq = g.next_seq.wrapping_add(seg.payload as u32);
                    // A short or pushed segment must be the last one.
                    g.closed = seg.psh || seg.payload < usize::from(g.gso_size);
                    continue;
                }
            }

            // Not mergeable with the open group: flush it to keep the flow in order.
            if let Some(s) = slot {
                let g = self.open.remove(s);
                Self::emit(&mut self.ops, g);
            }

            match seg {
                Some(seg) if !seg.psh => {
                    if self.open.len() == MAX_GROUPS {
                        let g = self.open.remove(0);
                        Self::emit(&mut self.ops, g);
                    }
                    let mut members = [0u8; MAX_SEGS];
                    members[0] = i as u8;
                    self.open.push(Group {
                        members,
                        n: 1,
                        gso_size: seg.payload as u16,
                        total_len: p.len() as u32,
                        next_seq: seg.seq.wrapping_add(seg.payload as u32),
                        closed: false,
                    });
                }
                _ => self.ops.push(Op::Single(i as u8)),
            }
        }
        for g in self.open.drain(..) {
            Self::emit(&mut self.ops, g);
        }
        &self.ops
    }
}

/// Fill `out` with the virtio header followed by the IP + TCP header of the
/// merged packet for `g`. Returns the number of bytes used; the caller appends
/// the first member's payload and then every other member's payload.
pub fn merged_header<'a>(
    g: &Group,
    pkt: impl Fn(usize) -> &'a [u8],
    out: &mut [u8; MERGED_HDR_MAX],
) -> usize {
    let members = g.members();
    let first = pkt(usize::from(members[0]));
    let last = pkt(usize::from(members[members.len() - 1]));
    let thl = usize::from(first[IPV4_HLEN + 12] >> 4) * 4;
    let hdr_len = IPV4_HLEN + thl;

    out[0] = VIRTIO_NET_HDR_F_NEEDS_CSUM;
    out[1] = VIRTIO_NET_HDR_GSO_TCPV4;
    out[2..4].copy_from_slice(&(hdr_len as u16).to_ne_bytes());
    out[4..6].copy_from_slice(&g.gso_size.to_ne_bytes());
    out[6..8].copy_from_slice(&(IPV4_HLEN as u16).to_ne_bytes());
    out[8..10].copy_from_slice(&16u16.to_ne_bytes());

    let h = &mut out[VNET_HDR_LEN..VNET_HDR_LEN + hdr_len];
    h.copy_from_slice(&first[..hdr_len]);
    // IP: new total length and header checksum.
    h[2..4].copy_from_slice(&(g.total_len as u16).to_be_bytes());
    h[10..12].fill(0);
    let ip_csum = !fold(sum_bytes(&h[..IPV4_HLEN], 0));
    h[10..12].copy_from_slice(&ip_csum.to_be_bytes());
    // TCP: PSH from the last segment; the checksum field holds the folded
    // pseudo-header sum, which is what a partial-checksum packet must carry.
    h[IPV4_HLEN + 13] |= last[IPV4_HLEN + 13] & TCP_FLAG_PSH;
    let tcp_len = g.total_len as usize - IPV4_HLEN;
    let psum = fold(pseudo_sum(first, tcp_len));
    h[IPV4_HLEN + 16..IPV4_HLEN + 18].copy_from_slice(&psum.to_be_bytes());

    VNET_HDR_LEN + hdr_len
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Flow {
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
        seq: u32,
        ack: u32,
        id: u16,
        ts: Option<(u32, u32)>,
    }

    impl Flow {
        fn new(sport: u16) -> Self {
            Self {
                src: [5, 161, 7, 195],
                dst: [100, 96, 0, 2],
                sport,
                dport: 40_000,
                seq: 0xffff_f000,
                ack: 77,
                id: 0xfffe,
                ts: Some((1000, 2000)),
            }
        }

        /// Build the next data segment with correct checksums.
        fn seg(&mut self, payload_len: usize, flags: u8) -> Vec<u8> {
            let thl = if self.ts.is_some() { 32 } else { 20 };
            let total = 20 + thl + payload_len;
            let mut p = vec![0u8; total];
            p[0] = 0x45;
            p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            p[4..6].copy_from_slice(&self.id.to_be_bytes());
            p[6] = 0x40;
            p[8] = 57;
            p[9] = 6;
            p[12..16].copy_from_slice(&self.src);
            p[16..20].copy_from_slice(&self.dst);
            let ipc = !fold(sum_bytes(&p[..20], 0));
            p[10..12].copy_from_slice(&ipc.to_be_bytes());
            p[20..22].copy_from_slice(&self.sport.to_be_bytes());
            p[22..24].copy_from_slice(&self.dport.to_be_bytes());
            p[24..28].copy_from_slice(&self.seq.to_be_bytes());
            p[28..32].copy_from_slice(&self.ack.to_be_bytes());
            p[32] = ((thl / 4) as u8) << 4;
            p[33] = flags;
            p[34..36].copy_from_slice(&501u16.to_be_bytes());
            if let Some((val, ecr)) = self.ts {
                p[40..44].copy_from_slice(&[1, 1, 8, 10]);
                p[44..48].copy_from_slice(&val.to_be_bytes());
                p[48..52].copy_from_slice(&ecr.to_be_bytes());
            }
            for (k, b) in p[20 + thl..].iter_mut().enumerate() {
                *b = (k as u32).wrapping_mul(31).wrapping_add(self.seq) as u8;
            }
            set_tcp_checksum(&mut p);
            self.seq = self.seq.wrapping_add(payload_len as u32);
            self.id = self.id.wrapping_add(1);
            p
        }
    }

    fn set_tcp_checksum(p: &mut [u8]) {
        p[36..38].fill(0);
        let c = !fold(sum_bytes(&p[20..], pseudo_sum(p, p.len() - 20)));
        p[36..38].copy_from_slice(&c.to_be_bytes());
    }

    fn plan(pkts: &[Vec<u8>]) -> Vec<Op> {
        Gro::new().plan(pkts.len(), |i| &pkts[i]).to_vec()
    }

    fn shape(ops: &[Op]) -> Vec<Vec<u8>> {
        ops.iter()
            .map(|op| match op {
                Op::Single(i) => vec![*i],
                Op::Merged(g) => g.members().to_vec(),
            })
            .collect()
    }

    /// What the kernel does with a merged packet: cut it back into segments.
    fn segment(g: &Group, pkts: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let mut hdr = [0u8; MERGED_HDR_MAX];
        let n = merged_header(g, |i| &pkts[i], &mut hdr);
        assert_eq!(hdr[0], 1);
        assert_eq!(hdr[1], 1);
        let hdr_len = usize::from(u16::from_ne_bytes([hdr[2], hdr[3]]));
        let gso = usize::from(u16::from_ne_bytes([hdr[4], hdr[5]]));
        assert_eq!(n, VNET_HDR_LEN + hdr_len);
        let h = &hdr[VNET_HDR_LEN..n];
        let mut payload = Vec::new();
        for &m in g.members() {
            payload.extend_from_slice(&pkts[usize::from(m)][hdr_len..]);
        }
        // The merged packet must be self-consistent.
        assert_eq!(
            usize::from(u16::from_be_bytes([h[2], h[3]])),
            hdr_len + payload.len()
        );
        assert_eq!(fold(sum_bytes(&h[..20], 0)), 0xffff);
        assert_eq!(
            u16::from_be_bytes([h[36], h[37]]),
            fold(pseudo_sum(h, hdr_len - 20 + payload.len()))
        );

        let id0 = u16::from_be_bytes([h[4], h[5]]);
        let seq0 = u32::from_be_bytes([h[24], h[25], h[26], h[27]]);
        let chunks: Vec<&[u8]> = payload.chunks(gso).collect();
        let mut out = Vec::new();
        for (k, c) in chunks.iter().enumerate() {
            let mut p = h.to_vec();
            p.extend_from_slice(c);
            let total = p.len() as u16;
            p[2..4].copy_from_slice(&total.to_be_bytes());
            p[4..6].copy_from_slice(&id0.wrapping_add(k as u16).to_be_bytes());
            p[10..12].fill(0);
            let ipc = !fold(sum_bytes(&p[..20], 0));
            p[10..12].copy_from_slice(&ipc.to_be_bytes());
            let seq = seq0.wrapping_add((k * gso) as u32);
            p[24..28].copy_from_slice(&seq.to_be_bytes());
            if k + 1 != chunks.len() {
                p[33] &= !TCP_FLAG_PSH;
            }
            set_tcp_checksum(&mut p);
            out.push(p);
        }
        out
    }

    fn assert_roundtrip(pkts: &[Vec<u8>], ops: &[Op]) {
        let mut seen = Vec::new();
        for op in ops {
            match op {
                Op::Single(i) => seen.push(*i),
                Op::Merged(g) => {
                    let segs = segment(g, pkts);
                    assert_eq!(segs.len(), g.members().len());
                    for (s, &m) in segs.iter().zip(g.members()) {
                        assert_eq!(s, &pkts[usize::from(m)], "segment {m} differs");
                        seen.push(m);
                    }
                }
            }
        }
        seen.sort_unstable();
        let all: Vec<u8> = (0..pkts.len() as u8).collect();
        assert_eq!(seen, all, "every packet written exactly once");
    }

    #[test]
    fn checksum_matches_reference() {
        // RFC 1071 example words: 0001 f203 f4f5 f6f7 -> sum ddf2, checksum 220d.
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(fold(sum_bytes(&data, 0)), 0xddf2);
        // Odd length: the last byte is the high byte of a padded word.
        assert_eq!(fold(sum_bytes(&[0x12, 0x34, 0x56], 0)), 0x1234 + 0x5600);
        assert_eq!(fold(sum_bytes(&[0xff; 7], 0)), fold(0xffff * 3 + 0xff00));
    }

    #[test]
    fn merges_consecutive_segments() {
        let mut f = Flow::new(80);
        let pkts: Vec<_> = (0..10).map(|_| f.seg(1228, TCP_FLAG_ACK)).collect();
        let ops = plan(&pkts);
        assert_eq!(shape(&ops), vec![(0..10).collect::<Vec<u8>>()]);
        assert_roundtrip(&pkts, &ops);
    }

    #[test]
    fn roundtrip_across_seq_and_id_wraparound_without_options() {
        let mut f = Flow::new(80);
        f.ts = None;
        let pkts: Vec<_> = (0..6).map(|_| f.seg(1240, TCP_FLAG_ACK)).collect();
        let ops = plan(&pkts);
        assert_eq!(shape(&ops).len(), 1);
        assert_roundtrip(&pkts, &ops);
    }

    #[test]
    fn short_or_pushed_segment_ends_group() {
        let mut f = Flow::new(80);
        let pkts = vec![
            f.seg(1228, TCP_FLAG_ACK),
            f.seg(1228, TCP_FLAG_ACK),
            f.seg(500, TCP_FLAG_ACK),
            f.seg(1228, TCP_FLAG_ACK),
            f.seg(1228, TCP_FLAG_ACK | TCP_FLAG_PSH),
            f.seg(1228, TCP_FLAG_ACK),
        ];
        let ops = plan(&pkts);
        assert_eq!(shape(&ops), vec![vec![0, 1, 2], vec![3, 4], vec![5]]);
        assert_roundtrip(&pkts, &ops);
    }

    #[test]
    fn larger_segment_is_not_appended() {
        let mut f = Flow::new(80);
        let pkts = vec![f.seg(600, TCP_FLAG_ACK), f.seg(1228, TCP_FLAG_ACK)];
        assert_eq!(shape(&plan(&pkts)), vec![vec![0], vec![1]]);
    }

    #[test]
    fn interleaved_flows_merge_separately() {
        let (mut a, mut b) = (Flow::new(80), Flow::new(443));
        let pkts = vec![
            a.seg(1228, TCP_FLAG_ACK),
            b.seg(1228, TCP_FLAG_ACK),
            a.seg(1228, TCP_FLAG_ACK),
            b.seg(1228, TCP_FLAG_ACK),
            a.seg(1228, TCP_FLAG_ACK),
        ];
        let ops = plan(&pkts);
        assert_eq!(shape(&ops), vec![vec![0, 2, 4], vec![1, 3]]);
        assert_roundtrip(&pkts, &ops);
    }

    #[test]
    fn gap_or_reordering_keeps_flow_order() {
        let mut f = Flow::new(80);
        let p0 = f.seg(1228, TCP_FLAG_ACK);
        let p1 = f.seg(1228, TCP_FLAG_ACK);
        let _lost = f.seg(1228, TCP_FLAG_ACK);
        let p3 = f.seg(1228, TCP_FLAG_ACK);
        let p4 = f.seg(1228, TCP_FLAG_ACK);
        let pkts = vec![p0, p1, p3, p4];
        let ops = plan(&pkts);
        assert_eq!(shape(&ops), vec![vec![0, 1], vec![2, 3]]);
        assert_roundtrip(&pkts, &ops);
    }

    #[test]
    fn changed_header_fields_split_groups() {
        // Timestamp change.
        let mut f = Flow::new(80);
        let p0 = f.seg(1228, TCP_FLAG_ACK);
        let p1 = f.seg(1228, TCP_FLAG_ACK);
        f.ts = Some((1001, 2000));
        let p2 = f.seg(1228, TCP_FLAG_ACK);
        // ACK number change.
        f.ack = 78;
        let p3 = f.seg(1228, TCP_FLAG_ACK);
        let p4 = f.seg(1228, TCP_FLAG_ACK);
        let pkts = vec![p0, p1, p2, p3, p4];
        let ops = plan(&pkts);
        assert_eq!(shape(&ops), vec![vec![0, 1], vec![2], vec![3, 4]]);
        assert_roundtrip(&pkts, &ops);
    }

    #[test]
    fn non_data_packets_pass_through_in_order() {
        let mut f = Flow::new(80);
        let p0 = f.seg(1228, TCP_FLAG_ACK);
        let p1 = f.seg(1228, TCP_FLAG_ACK);
        // FIN with data, a pure ACK, and a non-IP blob.
        let fin = f.seg(10, TCP_FLAG_ACK | 0x01);
        let ack = f.seg(0, TCP_FLAG_ACK);
        let junk = vec![0x60u8; 60];
        let pkts = vec![p0, p1, fin, ack, junk];
        let ops = plan(&pkts);
        assert_eq!(shape(&ops), vec![vec![0, 1], vec![2], vec![3], vec![4]]);
        assert_roundtrip(&pkts, &ops);
    }

    #[test]
    fn corrupt_segment_is_never_merged() {
        let mut f = Flow::new(80);
        let p0 = f.seg(1228, TCP_FLAG_ACK);
        let mut p1 = f.seg(1228, TCP_FLAG_ACK);
        p1[700] ^= 0x01;
        let p2 = f.seg(1228, TCP_FLAG_ACK);
        let p3 = f.seg(1228, TCP_FLAG_ACK);
        let pkts = vec![p0, p1, p2, p3];
        let ops = plan(&pkts);
        // The corrupt one goes out alone and untouched; order is preserved.
        assert_eq!(shape(&ops), vec![vec![0], vec![1], vec![2, 3]]);
        assert_roundtrip(&pkts, &ops);
    }

    #[test]
    fn fragments_and_ip_options_are_not_merged() {
        let mut f = Flow::new(80);
        let mut p0 = f.seg(1228, TCP_FLAG_ACK);
        p0[6] = 0x00; // DF clear
        let mut p1 = f.seg(1228, TCP_FLAG_ACK);
        p1[6] = 0x60; // DF + MF
        let pkts = vec![p0, p1, f.seg(1228, TCP_FLAG_ACK)];
        assert_eq!(shape(&plan(&pkts)), vec![vec![0], vec![1], vec![2]]);
    }

    #[test]
    fn merged_length_is_capped() {
        let mut f = Flow::new(80);
        let pkts: Vec<_> = (0..MAX_SEGS).map(|_| f.seg(1228, TCP_FLAG_ACK)).collect();
        let ops = plan(&pkts);
        for op in &ops {
            if let Op::Merged(g) = op {
                assert!(g.total_len as usize <= MAX_MERGED_LEN);
            }
        }
        assert!(ops.len() >= 2);
        assert_roundtrip(&pkts, &ops);
    }

    #[test]
    fn many_flows_overflow_group_table() {
        let mut flows: Vec<Flow> = (0..MAX_GROUPS as u16 + 4)
            .map(|i| Flow::new(1000 + i))
            .collect();
        let mut pkts = Vec::new();
        for _ in 0..2 {
            for f in &mut flows {
                pkts.push(f.seg(1228, TCP_FLAG_ACK));
            }
        }
        let ops = plan(&pkts);
        assert_roundtrip(&pkts, &ops);
    }
}
