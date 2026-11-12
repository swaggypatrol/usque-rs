//! MASQUE tunnel data path.
//!
//! The data path is a three-thread pipeline built on plain blocking syscalls:
//!
//! * the **QUIC thread** (the caller of [`maintain_tunnel`]) owns the QUIC
//!   connection, receives UDP in batches (`recvmmsg`), decrypts, and sends
//!   UDP in batches (`sendmmsg`);
//! * the **tun-tx thread** writes decrypted IP packets to the TUN device, so
//!   the kernel's per-packet IP stack work runs on another core;
//! * the **tun-rx thread** reads IP packets from the TUN device.
//!
//! Packets travel between threads in fixed-size [`Batch`]es that are recycled
//! through return channels, so the steady state allocates nothing.

use anyhow::{bail, Result};
use portable_atomic::{AtomicU64, Ordering};
use quiche::h3::NameValue;
use ring::rand::SecureRandom;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::Config;
use usque_rs::gro::{self, Gro, VNET_HDR_LEN};
use usque_rs::icmp;
use usque_rs::datagram::parse_datagram;
use usque_rs::packet;
use crate::tls;

const MAX_DATAGRAM_SIZE: usize = 1350;

/// Packets per batch (also the `recvmmsg`/`sendmmsg` vector length).
const BATCH_PKTS: usize = 64;
/// Bytes reserved per packet in a batch.
const SLOT: usize = 1664;
/// Space left in front of every packet in a slot: room for the QUIC datagram
/// prefix (uplink) or the virtio header (downlink).
const HEADROOM: usize = 16;
/// Bounded queue depth between threads, in batches.
const QUEUE_BATCHES: usize = 128;
/// Requested UDP socket buffer size.
const SOCK_BUF_BYTES: libc::c_int = 8 * 1024 * 1024;
/// TUN transmit queue length (packets waiting for tun-rx to read them).
const TUN_TXQUEUELEN: libc::c_int = 5000;
/// QUIC DATAGRAM receive queue length; it is drained after every `recvmmsg`.
const DGRAM_RECV_QUEUE_LEN: usize = 8192;
/// QUIC DATAGRAM send queue length. Packets wait here when the congestion
/// window is full, so it bounds the queueing delay the tunnel can add: beyond
/// it packets are dropped and the inner flows back off.
const DGRAM_SEND_QUEUE_LEN: usize = 1024;
/// Congestion controller for the tunnel's own packets. BBR2 keeps the uplink
/// moving on lossy or jittery links, where CUBIC stalled at a fraction of the
/// available rate. Override with `USQUE_CC=reno|cubic|bbr|bbr2`.
const DEFAULT_CC: &str = "bbr2";
/// The tunnel is considered dead when this many packets have gone out since
/// the last packet came back and that took at least `NO_RETURN_TIMEOUT`. The
/// proxy can stop forwarding while it keeps acknowledging at the QUIC level,
/// which neither the idle timeout nor the keepalive notices.
const NO_RETURN_PACKETS: u64 = 32;
const NO_RETURN_TIMEOUT: Duration = Duration::from_secs(12);
/// A session that ends sooner than this is followed by a pause before retrying.
const MIN_SESSION: Duration = Duration::from_secs(2);
/// Max `recvmmsg` rounds before ACKs are flushed.
const RX_ROUNDS: usize = 4;
/// Loop iterations between refreshes of the QUIC counters shown in the stats.
const STATS_EVERY: u32 = 64;
/// Max uplink packets handled per loop iteration.
const UP_PKTS_PER_ITER: usize = 512;

/// Packets dropped because an inter-thread queue was full.
static QUEUE_DROPS: AtomicU64 = AtomicU64::new(0);
/// Packets handed to the TUN writers, and the `write` calls that carried them.
static TUN_TX_PKTS: AtomicU64 = AtomicU64::new(0);
static TUN_TX_WRITES: AtomicU64 = AtomicU64::new(0);

/// Handle to the TUN device shared by the worker threads.
#[derive(Clone, Copy)]
struct Tun {
    fd: RawFd,
    /// Packets carry a `virtio_net_hdr` prefix in both directions.
    vnet: bool,
    /// Merge TCP segments before writing (needs `vnet`).
    gro: bool,
}

/// Configuration for a MASQUE tunnel session.
pub struct TunnelConfig {
    pub endpoint: SocketAddr,
    pub sni: String,
    pub keepalive_period: Duration,
    pub mtu: u32,
}

struct Stats {
    tx_packets: AtomicU64,
    rx_packets: AtomicU64,
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
    dropped: AtomicU64,
    quic_lost: AtomicU64,
    quic_retrans: AtomicU64,
    stop: AtomicBool,
}

impl Stats {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            tx_packets: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            quic_lost: AtomicU64::new(0),
            quic_retrans: AtomicU64::new(0),
            stop: AtomicBool::new(false),
        })
    }
}

fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {:02}s", secs / 60, secs % 60)
    } else {
        format!(
            "{}h {:02}m {:02}s",
            secs / 3600,
            (secs % 3600) / 60,
            secs % 60
        )
    }
}

// ---------------------------------------------------------------------------
// Batches and inter-thread plumbing
// ---------------------------------------------------------------------------

/// A fixed-capacity group of packets. Packet `i` lives in slot `i`
/// (`data[i * SLOT..]`); `pkts[i]` is its (offset within the slot, length).
struct Batch {
    data: Box<[u8]>,
    pkts: Vec<(u16, u16)>,
}

impl Batch {
    fn new() -> Self {
        Self {
            data: vec![0u8; BATCH_PKTS * SLOT].into_boxed_slice(),
            pkts: Vec::with_capacity(BATCH_PKTS),
        }
    }

    fn from_pool(pool: &Receiver<Self>) -> Self {
        pool.try_recv().map_or_else(
            |_| Self::new(),
            |mut b| {
                b.pkts.clear();
                b
            },
        )
    }
}

/// Wakes the QUIC thread out of `poll` when uplink packets are queued.
struct Waker {
    efd: RawFd,
    waiting: AtomicBool,
}

impl Waker {
    fn wake_if_waiting(&self) {
        if self.waiting.load(Ordering::SeqCst) {
            let one: u64 = 1;
            // SAFETY: efd is a valid eventfd; writing 8 bytes from a u64.
            unsafe {
                libc::write(self.efd, std::ptr::addr_of!(one).cast(), 8);
            }
        }
    }

    fn drain(&self) {
        let mut v: u64 = 0;
        // SAFETY: efd is a valid non-blocking eventfd; reading 8 bytes into a u64.
        unsafe {
            libc::read(self.efd, std::ptr::addr_of_mut!(v).cast(), 8);
        }
    }
}

/// The QUIC thread's handles to the TUN threads.
struct Io {
    tun: Tun,
    up_rx: Receiver<Batch>,
    up_ret: Sender<Batch>,
    /// One queue per tun-tx thread; a flow always maps to the same one.
    down_tx: Vec<SyncSender<Batch>>,
    down_pool: Receiver<Batch>,
    waker: Arc<Waker>,
}

impl Io {
    /// Hand a batch to tun-tx. Blocks while the queue is full; the kernel's UDP
    /// receive buffer absorbs the backlog meanwhile.
    fn push_down(&self, w: usize, b: Batch) {
        if b.pkts.is_empty() {
            return;
        }
        if let Err(mpsc::SendError(b)) = self.down_tx[w].send(b) {
            QUEUE_DROPS.fetch_add(b.pkts.len() as u64, Ordering::Relaxed);
        }
    }
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn poll_one(fd: RawFd, events: libc::c_short, timeout_ms: libc::c_int) -> bool {
    let mut p = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    // SAFETY: p is a valid pollfd for the duration of the call.
    let r = unsafe { libc::poll(&mut p, 1, timeout_ms) };
    r > 0
}

fn duration_to_poll_ms(d: Duration) -> libc::c_int {
    if d.is_zero() {
        return 0;
    }
    let ms = d.as_micros().div_ceil(1000);
    ms.min(60_000) as libc::c_int
}

fn set_nonblocking(fd: RawFd) -> Result<()> {
    // SAFETY: plain fcntl calls on a valid fd.
    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFL);
        if fl < 0 || libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK) < 0 {
            bail!("fcntl(O_NONBLOCK): {}", std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Ask for large socket buffers; the FORCE variants ignore `rmem_max`/`wmem_max` (needs root).
fn set_socket_buffers(fd: RawFd) {
    let v = SOCK_BUF_BYTES;
    for (force, plain) in [
        (libc::SO_RCVBUFFORCE, libc::SO_RCVBUF),
        (libc::SO_SNDBUFFORCE, libc::SO_SNDBUF),
    ] {
        // SAFETY: v outlives the calls; length matches the type.
        unsafe {
            let p = std::ptr::addr_of!(v).cast();
            let len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            if libc::setsockopt(fd, libc::SOL_SOCKET, force, p, len) != 0 {
                libc::setsockopt(fd, libc::SOL_SOCKET, plain, p, len);
            }
        }
    }
}

/// Lengthen the TUN transmit queue so bursts survive until tun-rx reads them.
fn set_txqueuelen(name: &str, qlen: libc::c_int) {
    // struct ifreq: 16 bytes of name followed by a 24-byte union (ifr_qlen is an int at its start).
    let mut ifr = [0u8; 40];
    let n = name.len().min(15);
    ifr[..n].copy_from_slice(&name.as_bytes()[..n]);
    ifr[16..20].copy_from_slice(&qlen.to_ne_bytes());
    // SAFETY: ifr is a correctly sized ifreq buffer; the socket is closed before returning.
    unsafe {
        let s = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if s >= 0 {
            if libc::ioctl(s, libc::SIOCSIFTXQLEN as _, ifr.as_mut_ptr()) != 0 {
                log::warn!(
                    "failed to set txqueuelen on {name}: {}",
                    std::io::Error::last_os_error()
                );
            }
            libc::close(s);
        }
    }
}

/// Pin the calling thread to one CPU. Keeps the pipeline stages on separate
/// cores; otherwise the scheduler's wake-affinity tends to stack them on one.
fn pin_current_thread(cpu: usize) {
    // SAFETY: cpu_set_t is plain old data; the set outlives the call.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(cpu, &mut set);
        if libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) != 0 {
            log::warn!(
                "failed to pin thread to CPU {cpu}: {}",
                std::io::Error::last_os_error()
            );
        }
    }
}

/// Thread placement: CPU for the QUIC thread, the tun-rx thread, and one per
/// tun-tx thread (their count is the number of writers).
struct Placement {
    quic: Option<usize>,
    rx: Option<usize>,
    writers: Vec<Option<usize>>,
}

/// `USQUE_PIN=quic,rx,tx0[,tx1...]` pins explicitly (one writer thread per
/// `tx` entry); `USQUE_PIN=off` disables pinning. By default, machines with
/// 4+ CPUs put the QUIC thread on CPU 2 and the TUN threads on CPU 3, leaving
/// CPUs 0 and 1 to the kernel's receive path.
fn placement() -> Placement {
    let unpinned = || Placement {
        quic: None,
        rx: None,
        writers: vec![None],
    };
    match std::env::var("USQUE_PIN") {
        Ok(v) if v == "off" => return unpinned(),
        Ok(v) => {
            let cpus: Vec<usize> = v.split(',').filter_map(|x| x.trim().parse().ok()).collect();
            if cpus.len() >= 3 {
                return Placement {
                    quic: Some(cpus[0]),
                    rx: Some(cpus[1]),
                    writers: cpus[2..].iter().map(|&c| Some(c)).collect(),
                };
            }
            log::warn!("ignoring malformed USQUE_PIN={v}");
        }
        Err(_) => {}
    }
    let ncpu = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    if ncpu >= 4 {
        Placement {
            quic: Some(2),
            rx: Some(3),
            writers: vec![Some(3)],
        }
    } else {
        unpinned()
    }
}

/// Hash the flow of an IP packet (addresses, protocol and, for unfragmented
/// TCP/UDP, ports) so that every packet of a flow picks the same writer.
fn flow_hash(ip: &[u8]) -> usize {
    let fold = |b: &[u8]| {
        b.chunks(4).fold(0u32, |acc, c| {
            let mut w = [0u8; 4];
            w[..c.len()].copy_from_slice(c);
            acc.rotate_left(5) ^ u32::from_be_bytes(w)
        })
    };
    let h = match ip.first().map(|b| b >> 4) {
        Some(4) if ip.len() >= 20 => {
            let ihl = ((ip[0] & 0x0f) as usize) * 4;
            let proto = ip[9];
            let frag = u16::from_be_bytes([ip[6], ip[7]]) & 0x3fff != 0;
            let mut h = fold(&ip[12..20]) ^ u32::from(proto);
            if !frag && (proto == 6 || proto == 17) && ip.len() >= ihl + 4 {
                h = h.rotate_left(7) ^ fold(&ip[ihl..ihl + 4]);
            }
            h
        }
        Some(6) if ip.len() >= 40 => {
            let proto = ip[6];
            let mut h = fold(&ip[8..40]) ^ u32::from(proto);
            if (proto == 6 || proto == 17) && ip.len() >= 44 {
                h = h.rotate_left(7) ^ fold(&ip[40..44]);
            }
            h
        }
        _ => 0,
    };
    (h.wrapping_mul(0x9E37_79B1) >> 16) as usize
}

/// Write one buffer to the TUN device, waiting briefly if it is not writable.
fn write_tun_raw(fd: RawFd, buf: &[u8]) -> bool {
    let mut retried = false;
    loop {
        // SAFETY: buf is a valid slice for the duration of the call.
        let r = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if r >= 0 {
            return true;
        }
        match errno() {
            libc::EINTR => {}
            libc::EAGAIN if !retried => {
                retried = true;
                poll_one(fd, libc::POLLOUT, 5);
            }
            _ => return false,
        }
    }
}

/// Write a standalone IP packet (used off the fast path, e.g. for ICMP replies).
fn write_tun(tun: Tun, pkt: &[u8]) {
    if tun.vnet {
        let mut buf = Vec::with_capacity(VNET_HDR_LEN + pkt.len());
        buf.extend_from_slice(&[0u8; VNET_HDR_LEN]);
        buf.extend_from_slice(pkt);
        write_tun_raw(tun.fd, &buf);
    } else {
        write_tun_raw(tun.fd, pkt);
    }
}

/// Write several buffers as one TUN packet.
fn writev_tun(fd: RawFd, iov: &[libc::iovec]) -> bool {
    let mut retried = false;
    loop {
        // SAFETY: every iovec points into a live buffer owned by the caller.
        let r = unsafe { libc::writev(fd, iov.as_ptr(), iov.len() as libc::c_int) };
        if r >= 0 {
            return true;
        }
        match errno() {
            libc::EINTR => {}
            libc::EAGAIN if !retried => {
                retried = true;
                poll_one(fd, libc::POLLOUT, 5);
            }
            _ => return false,
        }
    }
}

fn tun_writer(tun: Tun, down_rx: &Receiver<Batch>, ret: &Sender<Batch>) {
    let mut planner = Gro::new();
    let mut hdr = [0u8; gro::MERGED_HDR_MAX];
    let mut iov: Vec<libc::iovec> = Vec::with_capacity(gro::MAX_SEGS + 1);
    let pre = if tun.vnet { VNET_HDR_LEN } else { 0 };

    while let Ok(mut b) = down_rx.recv() {
        let n = b.pkts.len();
        // Zero the virtio header in front of every packet: "no offload".
        if tun.vnet {
            for (i, &(off, _)) in b.pkts.iter().enumerate() {
                let start = i * SLOT + off as usize;
                b.data[start - VNET_HDR_LEN..start].fill(0);
            }
        }
        let data = &b.data;
        let pkts = &b.pkts;
        let pkt = |i: usize| {
            let (off, len) = pkts[i];
            let start = i * SLOT + off as usize;
            &data[start..start + len as usize]
        };
        // A packet together with the virtio header in front of it.
        let framed = |i: usize| {
            let (off, len) = pkts[i];
            let start = i * SLOT + off as usize;
            &data[start - pre..start + len as usize]
        };

        let mut writes = 0u64;
        if tun.gro && n > 1 {
            for op in planner.plan(n, pkt) {
                match op {
                    gro::Op::Single(i) => {
                        write_tun_raw(tun.fd, framed(usize::from(*i)));
                        writes += 1;
                    }
                    gro::Op::Merged(g) => {
                        let hlen = gro::merged_header(g, pkt, &mut hdr);
                        let ip_tcp = hlen - VNET_HDR_LEN;
                        iov.clear();
                        iov.push(libc::iovec {
                            iov_base: hdr.as_mut_ptr().cast(),
                            iov_len: hlen,
                        });
                        for &m in g.members() {
                            let payload = &pkt(usize::from(m))[ip_tcp..];
                            iov.push(libc::iovec {
                                iov_base: payload.as_ptr().cast_mut().cast(),
                                iov_len: payload.len(),
                            });
                        }
                        if writev_tun(tun.fd, &iov) {
                            writes += 1;
                        } else {
                            // The kernel refused the merged packet: send the originals.
                            for &m in g.members() {
                                write_tun_raw(tun.fd, framed(usize::from(m)));
                                writes += 1;
                            }
                        }
                    }
                }
            }
        } else {
            for i in 0..n {
                write_tun_raw(tun.fd, framed(i));
            }
            writes = n as u64;
        }
        TUN_TX_PKTS.fetch_add(n as u64, Ordering::Relaxed);
        TUN_TX_WRITES.fetch_add(writes, Ordering::Relaxed);
        let _ = ret.send(b);
    }
}

fn tun_reader(tun: Tun, up_tx: &SyncSender<Batch>, pool: &Receiver<Batch>, waker: &Waker) {
    let fd = tun.fd;
    let pre = if tun.vnet { VNET_HDR_LEN } else { 0 };
    let mut spare: Option<Batch> = None;
    loop {
        poll_one(fd, libc::POLLIN, -1);
        let mut b = spare.take().unwrap_or_else(|| Batch::from_pool(pool));
        b.pkts.clear();
        while b.pkts.len() < BATCH_PKTS {
            let i = b.pkts.len();
            // The virtio header (if any) lands in the headroom; the IP packet
            // always starts at HEADROOM.
            let slot = &mut b.data[i * SLOT + HEADROOM - pre..(i + 1) * SLOT];
            // SAFETY: slot is a valid mutable slice for the duration of the call.
            let n = unsafe { libc::read(fd, slot.as_mut_ptr().cast(), slot.len()) };
            if n < 0 {
                match errno() {
                    libc::EAGAIN => break,
                    libc::EINTR => continue,
                    e => {
                        eprintln!(
                            "\nTUN read failed: {}",
                            std::io::Error::from_raw_os_error(e)
                        );
                        std::process::exit(1);
                    }
                }
            }
            if n == 0 {
                eprintln!("\nTUN device closed");
                std::process::exit(1);
            }
            let n = n as usize;
            if n <= pre {
                continue;
            }
            // We never enable TUN offloads, so the kernel must hand us plain
            // packets; anything else cannot be forwarded as-is.
            if tun.vnet && (slot[0] != 0 || slot[1] != 0) {
                QUEUE_DROPS.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let len = n - pre;
            if packet::prepare_outgoing(&mut slot[pre..n]).is_ok() {
                b.pkts.push((HEADROOM as u16, len as u16));
            }
        }
        if b.pkts.is_empty() {
            spare = Some(b);
            continue;
        }
        // Block when the queue is full: packets then pile up in the TUN queue and the
        // next read picks them up as one large batch, instead of being dropped here.
        if up_tx.send(b).is_err() {
            return;
        }
        waker.wake_if_waiting();
    }
}

// ---------------------------------------------------------------------------
// recvmmsg / sendmmsg buffers
// ---------------------------------------------------------------------------

/// Pre-wired `mmsghdr` vector over one contiguous buffer. The boxed slices
/// never move, so the raw pointers inside stay valid for the struct's life.
struct Mmsg {
    bufs: Box<[u8]>,
    iovs: Box<[libc::iovec]>,
    hdrs: Box<[libc::mmsghdr]>,
    slot: usize,
}

impl Mmsg {
    fn new(n: usize, slot: usize) -> Self {
        let mut bufs = vec![0u8; n * slot].into_boxed_slice();
        let base = bufs.as_mut_ptr();
        let mut iovs: Box<[libc::iovec]> = (0..n)
            .map(|i| libc::iovec {
                // SAFETY: i * slot is within the allocation.
                iov_base: unsafe { base.add(i * slot) }.cast(),
                iov_len: slot,
            })
            .collect();
        let iov_base = iovs.as_mut_ptr();
        let hdrs: Box<[libc::mmsghdr]> = (0..n)
            .map(|i| {
                // SAFETY: mmsghdr is plain old data; all-zero is a valid value.
                let mut h: libc::mmsghdr = unsafe { std::mem::zeroed() };
                // SAFETY: i is within the iovs allocation.
                h.msg_hdr.msg_iov = unsafe { iov_base.add(i) };
                h.msg_hdr.msg_iovlen = 1 as _;
                h
            })
            .collect();
        Self {
            bufs,
            iovs,
            hdrs,
            slot,
        }
    }

    /// Receive up to the vector length without blocking. Returns the packet count.
    fn recv(&mut self, fd: RawFd, vlen: usize) -> usize {
        // SAFETY: hdrs/iovs/bufs are wired consistently in `new`.
        let n = unsafe {
            libc::recvmmsg(
                fd,
                self.hdrs.as_mut_ptr(),
                vlen.min(self.hdrs.len()) as _,
                libc::MSG_DONTWAIT as _,
                std::ptr::null_mut(),
            )
        };
        if n > 0 {
            n as usize
        } else {
            0
        }
    }

    fn pkt_mut(&mut self, i: usize) -> &mut [u8] {
        let len = (self.hdrs[i].msg_len as usize).min(self.slot);
        &mut self.bufs[i * self.slot..i * self.slot + len]
    }

    fn slot_mut(&mut self, i: usize) -> &mut [u8] {
        &mut self.bufs[i * self.slot..(i + 1) * self.slot]
    }

    /// Send the first `count` slots, whose lengths were set with `set_len`.
    fn send(&mut self, fd: RawFd, count: usize) {
        let mut done = 0;
        let mut retried = false;
        while done < count {
            // SAFETY: hdrs[done..count] are valid and wired to live buffers.
            let n = unsafe {
                libc::sendmmsg(fd, self.hdrs.as_mut_ptr().add(done), (count - done) as _, 0)
            };
            if n > 0 {
                done += n as usize;
                continue;
            }
            match errno() {
                libc::EINTR => {}
                libc::EAGAIN if !retried => {
                    retried = true;
                    poll_one(fd, libc::POLLOUT, 5);
                }
                e => {
                    log::warn!("UDP send error: {}", std::io::Error::from_raw_os_error(e));
                    return;
                }
            }
        }
    }

    fn set_len(&mut self, i: usize, len: usize) {
        self.iovs[i].iov_len = len;
    }
}

/// Feed every UDP packet currently queued on the socket into the connection.
/// Returns the number of packets received.
fn recv_all(
    conn: &mut quiche::Connection,
    rx: &mut Mmsg,
    fd: RawFd,
    recv_info: quiche::RecvInfo,
    max_rounds: usize,
) -> usize {
    let mut total = 0;
    for _ in 0..max_rounds {
        let n = rx.recv(fd, BATCH_PKTS);
        for i in 0..n {
            if let Err(e) = conn.recv(rx.pkt_mut(i), recv_info) {
                log::debug!("quic recv error: {e}");
            }
        }
        total += n;
        if n < BATCH_PKTS {
            break;
        }
    }
    total
}

/// Send everything the connection wants to send. Returns the packet count.
fn flush(conn: &mut quiche::Connection, tx: &mut Mmsg, fd: RawFd) -> Result<usize> {
    let mut total = 0;
    loop {
        let mut k = 0;
        while k < BATCH_PKTS {
            match conn.send(tx.slot_mut(k)) {
                Ok((write, _)) => {
                    tx.set_len(k, write);
                    k += 1;
                }
                Err(quiche::Error::Done) => break,
                Err(e) => bail!("quic send error: {e}"),
            }
        }
        if k == 0 {
            return Ok(total);
        }
        tx.send(fd, k);
        total += k;
        if k < BATCH_PKTS {
            return Ok(total);
        }
    }
}

// ---------------------------------------------------------------------------
// Tunnel lifecycle
// ---------------------------------------------------------------------------

/// Run the MASQUE tunnel, reconnecting on-demand when traffic arrives.
/// Blocks the calling thread forever (it becomes the QUIC thread).
pub fn maintain_tunnel(
    config: &Config,
    tunnel_cfg: &TunnelConfig,
    tun_dev: &crate::tun_device::TunDev,
) -> Result<()> {
    if tunnel_cfg.mtu as usize + HEADROOM > SLOT - 64 {
        bail!("MTU {} is too large", tunnel_cfg.mtu);
    }

    let tun = Tun {
        fd: tun_dev.as_raw_fd(),
        vnet: tun_dev.vnet_hdr,
        gro: tun_dev.vnet_hdr && std::env::var("USQUE_GRO").map_or(true, |v| v != "0"),
    };
    set_nonblocking(tun.fd)?;
    set_txqueuelen(&tun_dev.name, TUN_TXQUEUELEN);
    log::info!("TUN offload: vnet_hdr={} tcp-merge={}", tun.vnet, tun.gro);

    // SAFETY: plain eventfd creation.
    let efd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
    if efd < 0 {
        bail!("eventfd: {}", std::io::Error::last_os_error());
    }
    let waker = Arc::new(Waker {
        efd,
        waiting: AtomicBool::new(false),
    });

    let (up_tx, up_rx) = mpsc::sync_channel::<Batch>(QUEUE_BATCHES);
    let (up_ret, up_pool) = mpsc::channel::<Batch>();
    let (down_ret, down_pool) = mpsc::channel::<Batch>();

    let place = placement();
    let reader_waker = waker.clone();
    let rx_cpu = place.rx;
    std::thread::Builder::new()
        .name("tun-rx".into())
        .spawn(move || {
            if let Some(c) = rx_cpu {
                pin_current_thread(c);
            }
            tun_reader(tun, &up_tx, &up_pool, &reader_waker);
        })?;
    let mut down_tx = Vec::new();
    for (i, cpu) in place.writers.iter().copied().enumerate() {
        let (tx, down_rx) = mpsc::sync_channel::<Batch>(QUEUE_BATCHES);
        let ret = down_ret.clone();
        std::thread::Builder::new()
            .name(format!("tun-tx{i}"))
            .spawn(move || {
                if let Some(c) = cpu {
                    pin_current_thread(c);
                }
                tun_writer(tun, &down_rx, &ret);
            })?;
        down_tx.push(tx);
    }
    if let Some(c) = place.quic {
        pin_current_thread(c);
    }

    let io = Io {
        tun,
        up_rx,
        up_ret,
        down_tx,
        down_pool,
        waker,
    };

    loop {
        // Wait for TUN traffic before connecting
        eprint!("\r\x1b[2K[idle] Waiting for traffic...");
        let Ok(first) = io.up_rx.recv() else {
            bail!("TUN reader thread exited");
        };

        eprintln!("\r\x1b[2K[connecting] {} ...", tunnel_cfg.endpoint);

        let started = Instant::now();
        match run_tunnel_session(config, tunnel_cfg, &io, first) {
            Ok(()) => eprintln!("\r\x1b[2K[disconnected] Session ended"),
            Err(e) => eprintln!("\r\x1b[2K[error] {e:#}"),
        }
        io.waker.waiting.store(false, Ordering::SeqCst);
        // Do not spin when the network is down and traffic keeps arriving.
        if started.elapsed() < MIN_SESSION {
            std::thread::sleep(Duration::from_secs(1));
        }
        // Loop back to idle
    }
}

/// Live one-line statistics. Only shown on a terminal: redirected to a file
/// the line would be appended every second and grow without bound.
/// `USQUE_STATS=1` forces it on, `USQUE_STATS=0` off.
fn spawn_stats_printer(stats: Arc<Stats>, session_start: Instant) {
    let enabled = match std::env::var("USQUE_STATS").as_deref() {
        Ok("0") => false,
        Ok(_) => true,
        // SAFETY: isatty only inspects the descriptor.
        Err(_) => unsafe { libc::isatty(2) == 1 },
    };
    if !enabled {
        return;
    }
    let _ = std::thread::Builder::new()
        .name("stats".into())
        .spawn(move || loop {
            std::thread::sleep(Duration::from_secs(1));
            if stats.stop.load(Ordering::Relaxed) {
                return;
            }
            eprint!(
                "\r\x1b[2K[connected {}] tx: {} ({})  rx: {} ({})  drop: {}  qdrop: {}  lost: {}  retrans: {}  tun-tx: {} pkts / {} writes",
                format_duration(session_start.elapsed()),
                stats.tx_packets.load(Ordering::Relaxed),
                format_bytes(stats.tx_bytes.load(Ordering::Relaxed)),
                stats.rx_packets.load(Ordering::Relaxed),
                format_bytes(stats.rx_bytes.load(Ordering::Relaxed)),
                stats.dropped.load(Ordering::Relaxed),
                QUEUE_DROPS.load(Ordering::Relaxed),
                stats.quic_lost.load(Ordering::Relaxed),
                stats.quic_retrans.load(Ordering::Relaxed),
                TUN_TX_PKTS.load(Ordering::Relaxed),
                TUN_TX_WRITES.load(Ordering::Relaxed),
            );
        });
}

/// Debug aid (`USQUE_SEQDIAG=1`): watches downlink TCP sequence numbers to tell
/// how many inner packets went missing before they reached this client.
/// A "gap" is a jump ahead in a flow's sequence space; a "late" packet fills an
/// earlier gap, either quickly (reordering) or after ~an RTT (retransmission).
struct SeqDiag {
    flows: Vec<(u64, u32, Instant)>,
    pkts: u64,
    gaps: u64,
    gap_pkts_est: u64,
    late_fast: u64,
    late_slow: u64,
    last_print: Instant,
}

impl SeqDiag {
    fn new() -> Self {
        Self {
            flows: vec![(0, 0, Instant::now()); 256],
            pkts: 0,
            gaps: 0,
            gap_pkts_est: 0,
            late_fast: 0,
            late_slow: 0,
            last_print: Instant::now(),
        }
    }

    fn observe(&mut self, ip: &[u8]) {
        if ip.len() < 40 || ip[0] >> 4 != 4 || ip[9] != 6 {
            return;
        }
        let ihl = ((ip[0] & 0x0f) as usize) * 4;
        let total = u16::from_be_bytes([ip[2], ip[3]]) as usize;
        if ip.len() < ihl + 20 || total < ihl + 20 {
            return;
        }
        let tcp = &ip[ihl..];
        let doff = ((tcp[12] >> 4) as usize) * 4;
        let payload = total.saturating_sub(ihl + doff) as u32;
        if payload == 0 {
            return;
        }
        let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
        let key = (u64::from(u32::from_be_bytes([ip[12], ip[13], ip[14], ip[15]])) << 32)
            | u64::from(u32::from_be_bytes([tcp[0], tcp[1], tcp[2], tcp[3]]));
        let idx = flow_hash(ip) % self.flows.len();
        let now = Instant::now();
        let f = &mut self.flows[idx];
        self.pkts += 1;
        if f.0 != key {
            *f = (key, seq.wrapping_add(payload), now);
            return;
        }
        // Distance ahead of the expected sequence number, modulo 2^32; the
        // upper half of the range means the segment is behind it.
        let ahead = seq.wrapping_sub(f.1);
        if ahead == 0 {
            f.1 = seq.wrapping_add(payload);
        } else if ahead < 0x8000_0000 {
            self.gaps += 1;
            self.gap_pkts_est += u64::from(ahead).div_ceil(u64::from(payload.max(1)));
            f.1 = seq.wrapping_add(payload);
            f.2 = now;
        } else if now.duration_since(f.2) < Duration::from_millis(15) {
            self.late_fast += 1;
        } else {
            self.late_slow += 1;
        }
    }

    fn maybe_print(&mut self, conn: &quiche::Connection) {
        if self.last_print.elapsed() < Duration::from_secs(5) {
            return;
        }
        self.last_print = Instant::now();
        if let Some(ps) = conn.path_stats().next() {
            eprintln!(
                "\n[quic] cwnd={} rtt={:?} sendq={} recvq={} sent={} lost={}",
                ps.cwnd,
                ps.rtt,
                conn.dgram_send_queue_len(),
                conn.dgram_recv_queue_len(),
                ps.sent,
                ps.lost,
            );
        }
        if self.pkts == 0 {
            return;
        }
        eprintln!(
            "\n[seqdiag 5s] tcp_pkts={} gaps={} missing_pkts~{} ({:.3}%) late_fast(reorder)={} late_slow(retx)={} ({:.3}%)",
            self.pkts,
            self.gaps,
            self.gap_pkts_est,
            100.0 * self.gap_pkts_est as f64 / self.pkts as f64,
            self.late_fast,
            self.late_slow,
            100.0 * self.late_slow as f64 / self.pkts as f64,
        );
        self.pkts = 0;
        self.gaps = 0;
        self.gap_pkts_est = 0;
        self.late_fast = 0;
        self.late_slow = 0;
    }
}

/// Move every received datagram into the per-writer batches in `cur`,
/// handing full batches to their tun-tx thread.
fn drain_dgrams(
    conn: &mut quiche::Connection,
    flow_id: u64,
    io: &Io,
    cur: &mut [Batch],
    stats: &Stats,
    mut diag: Option<&mut SeqDiag>,
) -> u64 {
    let mut pkts = 0u64;
    let mut bytes = 0u64;
    let writers = cur.len();
    let mut head = [0u8; 80];
    loop {
        // Pick the writer from the flow of the packet before copying it out.
        let w = if writers > 1 {
            match conn.dgram_recv_peek(&mut head, 80) {
                Ok(n) => parse_datagram(&head[..n], flow_id).map_or(0, flow_hash) % writers,
                Err(_) => break,
            }
        } else {
            0
        };
        let b = &mut cur[w];
        if b.pkts.len() == BATCH_PKTS {
            let full = std::mem::replace(b, Batch::from_pool(&io.down_pool));
            io.push_down(w, full);
        }
        let i = b.pkts.len();
        let slot = &mut b.data[i * SLOT + HEADROOM..(i + 1) * SLOT];
        match conn.dgram_recv(slot) {
            Ok(n) => {
                if let Some(payload) = parse_datagram(&slot[..n], flow_id) {
                    if packet::validate_incoming(payload).is_ok() {
                        let len = payload.len();
                        if let Some(d) = diag.as_deref_mut() {
                            d.observe(payload);
                        }
                        b.pkts.push(((HEADROOM + n - len) as u16, len as u16));
                        pkts += 1;
                        bytes += len as u64;
                    }
                }
            }
            Err(quiche::Error::Done) => break,
            Err(e) => {
                // Oversized or broken datagram: discard it so the queue keeps moving.
                log::debug!("dgram recv error: {e}");
                if conn.dgram_recv_vec().is_err() {
                    break;
                }
            }
        }
    }
    if pkts > 0 {
        stats.rx_packets.fetch_add(pkts, Ordering::Relaxed);
        stats.rx_bytes.fetch_add(bytes, Ordering::Relaxed);
    }
    pkts
}

/// Queue one batch of TUN packets as QUIC datagrams. Returns how many were queued.
fn send_up_batch(
    conn: &mut quiche::Connection,
    flow_prefix: &[u8],
    io: &Io,
    b: &mut Batch,
    stats: &Stats,
) -> u64 {
    let mut pkts = 0u64;
    let mut bytes = 0u64;
    let mut dropped = 0u64;
    let plen = flow_prefix.len();
    for (i, &(off, len)) in b.pkts.iter().enumerate() {
        let (off, len) = (off as usize, len as usize);
        let start = i * SLOT + off - plen;
        b.data[start..start + plen].copy_from_slice(flow_prefix);
        match conn.dgram_send(&b.data[start..start + plen + len]) {
            Ok(()) => {
                pkts += 1;
                bytes += len as u64;
            }
            Err(quiche::Error::InvalidState) => {
                log::warn!("datagram send: peer doesn't support datagrams");
            }
            Err(quiche::Error::Done) => dropped += 1,
            Err(e) => {
                dropped += 1;
                log::debug!("datagram send error: {e}, generating ICMP");
                let pkt = &b.data[i * SLOT + off..i * SLOT + off + len];
                if let Some(icmp_pkt) = icmp::compose_icmp_too_large(pkt, 1280) {
                    write_tun(io.tun, &icmp_pkt);
                }
            }
        }
    }
    stats.tx_packets.fetch_add(pkts, Ordering::Relaxed);
    stats.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
    if dropped > 0 {
        stats.dropped.fetch_add(dropped, Ordering::Relaxed);
    }
    pkts
}

fn run_tunnel_session(
    config: &Config,
    tunnel_cfg: &TunnelConfig,
    io: &Io,
    first: Batch,
) -> Result<()> {
    let tls_material = tls::prepare_tls_material(config)?;

    let mut quic_config = quiche::Config::new(quiche::PROTOCOL_VERSION)
        .map_err(|e| anyhow::anyhow!("quiche config: {e}"))?;

    quic_config.verify_peer(false);
    quic_config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .map_err(|e| anyhow::anyhow!("set ALPN: {e}"))?;
    quic_config
        .load_cert_chain_from_pem_file(tls_material.cert_pem_file.path().to_str().unwrap())
        .map_err(|e| anyhow::anyhow!("load cert: {e}"))?;
    quic_config
        .load_priv_key_from_pem_file(tls_material.key_pem_file.path().to_str().unwrap())
        .map_err(|e| anyhow::anyhow!("load key: {e}"))?;

    // We send a keepalive every `keepalive_period`; if nothing comes back for
    // two periods the peer is gone (or the path changed) and the session ends,
    // so the next packet from the TUN device triggers a fresh connection.
    let keepalive = tunnel_cfg.keepalive_period;
    let idle_ms = if keepalive.is_zero() {
        0
    } else {
        (keepalive * 2 + Duration::from_secs(5)).as_millis() as u64
    };
    quic_config.set_max_idle_timeout(idle_ms);
    quic_config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    quic_config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    quic_config.set_initial_max_data(10_000_000);
    quic_config.set_initial_max_stream_data_bidi_local(1_000_000);
    quic_config.set_initial_max_stream_data_bidi_remote(1_000_000);
    quic_config.set_initial_max_stream_data_uni(1_000_000);
    quic_config.set_initial_max_streams_bidi(100);
    quic_config.set_initial_max_streams_uni(100);
    quic_config.set_disable_active_migration(true);
    quic_config.enable_dgram(true, DGRAM_RECV_QUEUE_LEN, DGRAM_SEND_QUEUE_LEN);
    let cc = std::env::var("USQUE_CC").unwrap_or_else(|_| DEFAULT_CC.into());
    if let Err(e) = quic_config.set_cc_algorithm_name(&cc) {
        log::warn!("unknown congestion controller {cc:?} ({e}), using the default");
    }

    let bind_addr: SocketAddr = match tunnel_cfg.endpoint {
        SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
    };

    let socket = std::net::UdpSocket::bind(bind_addr)?;
    socket.connect(tunnel_cfg.endpoint)?;
    socket.set_nonblocking(true)?;
    let local_addr = socket.local_addr()?;
    let udp_fd = socket.as_raw_fd();
    set_socket_buffers(udp_fd);

    let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
    ring::rand::SystemRandom::new()
        .fill(&mut scid)
        .map_err(|_| anyhow::anyhow!("RNG failure"))?;
    let scid = quiche::ConnectionId::from_ref(&scid);

    let mut conn = quiche::connect(
        Some(&tunnel_cfg.sni),
        &scid,
        local_addr,
        tunnel_cfg.endpoint,
        &mut quic_config,
    )
    .map_err(|e| anyhow::anyhow!("quiche connect: {e}"))?;

    let recv_info = quiche::RecvInfo {
        to: local_addr,
        from: tunnel_cfg.endpoint,
    };
    let mut rx = Mmsg::new(BATCH_PKTS, 2048);
    let mut tx = Mmsg::new(BATCH_PKTS, MAX_DATAGRAM_SIZE);

    flush(&mut conn, &mut tx, udp_fd).map_err(|e| anyhow::anyhow!("initial send: {e}"))?;

    // One handshake-phase step: wait for UDP or the QUIC timer, then feed the connection.
    let step = |conn: &mut quiche::Connection, rx: &mut Mmsg| {
        let timeout = conn.timeout().unwrap_or(Duration::from_millis(100));
        if poll_one(udp_fd, libc::POLLIN, duration_to_poll_ms(timeout)) {
            recv_all(conn, rx, udp_fd, recv_info, RX_ROUNDS);
        } else {
            conn.on_timeout();
        }
    };

    // Complete handshake
    let handshake_deadline = Instant::now() + Duration::from_secs(15);
    loop {
        step(&mut conn, &mut rx);
        flush(&mut conn, &mut tx, udp_fd)?;

        if conn.is_established() {
            break;
        }
        if conn.is_closed() {
            bail!("connection closed during handshake");
        }
        if Instant::now() > handshake_deadline {
            bail!("handshake timed out");
        }
    }

    // Verify endpoint key pinning
    if let Some(peer_cert) = conn.peer_cert() {
        if !tls::verify_endpoint_key(peer_cert, &tls_material.endpoint_pub_key_spki_der) {
            bail!("peer certificate public key does not match pinned endpoint key");
        }
        log::debug!("Endpoint key pinning verified");
    } else {
        log::warn!("No peer certificate received; skipping key pinning");
    }

    // Set up HTTP/3
    let mut h3_config = quiche::h3::Config::new().map_err(|e| anyhow::anyhow!("h3 config: {e}"))?;
    h3_config.enable_extended_connect(true);

    let mut h3_conn = quiche::h3::Connection::with_transport(&mut conn, &h3_config)
        .map_err(|e| anyhow::anyhow!("h3 connection: {e}"))?;

    // Send CONNECT request for cf-connect-ip
    let req = vec![
        quiche::h3::Header::new(b":method", b"CONNECT"),
        quiche::h3::Header::new(b":protocol", b"cf-connect-ip"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", b"cloudflareaccess.com"),
        quiche::h3::Header::new(b":path", b"/"),
        quiche::h3::Header::new(b"capsule-protocol", b"?1"),
        quiche::h3::Header::new(b"user-agent", b""),
    ];

    let stream_id = h3_conn
        .send_request(&mut conn, &req, false)
        .map_err(|e| anyhow::anyhow!("send CONNECT request: {e}"))?;

    let flow_id = stream_id / 4;
    log::debug!("CONNECT request sent on stream {stream_id}, flow_id={flow_id}");

    flush(&mut conn, &mut tx, udp_fd)?;

    // Wait for 2xx
    let mut connect_established = false;
    for _ in 0..100 {
        step(&mut conn, &mut rx);

        loop {
            match h3_conn.poll(&mut conn) {
                Ok((sid, quiche::h3::Event::Headers { list, .. })) if sid == stream_id => {
                    for h in &list {
                        if h.name() == b":status" {
                            let status = std::str::from_utf8(h.value()).unwrap_or("?");
                            log::debug!("CONNECT response status: {status}");
                            if status.starts_with('2') {
                                connect_established = true;
                            } else {
                                bail!("CONNECT rejected with status {status}");
                            }
                        }
                    }
                }
                Ok(_) => {}
                Err(quiche::h3::Error::Done) => break,
                Err(e) => bail!("h3 poll error: {e}"),
            }
        }

        flush(&mut conn, &mut tx, udp_fd)?;

        if connect_established {
            break;
        }
        if conn.is_closed() {
            bail!("connection closed before CONNECT response");
        }
    }

    if !connect_established {
        bail!("timed out waiting for CONNECT response");
    }

    eprintln!("\r\x1b[2K[connected] MASQUE tunnel established");

    let stats = Stats::new();
    spawn_stats_printer(stats.clone(), Instant::now());

    let result = forward(
        &mut conn,
        &mut h3_conn,
        io,
        first,
        stream_id,
        udp_fd,
        recv_info,
        tunnel_cfg.keepalive_period,
        &mut rx,
        &mut tx,
        &stats,
    );

    stats.stop.store(true, Ordering::Relaxed);
    if !conn.is_closed() {
        // We are abandoning a connection the peer still considers open.
        conn.close(true, 0x100, b"").ok();
        flush(&mut conn, &mut tx, udp_fd).ok();
    }
    result
}

/// Main data forwarding loop (runs on the QUIC thread).
#[allow(clippy::too_many_arguments)]
fn forward(
    conn: &mut quiche::Connection,
    h3_conn: &mut quiche::h3::Connection,
    io: &Io,
    first: Batch,
    stream_id: u64,
    udp_fd: RawFd,
    recv_info: quiche::RecvInfo,
    keepalive_interval: Duration,
    rx: &mut Mmsg,
    tx: &mut Mmsg,
    stats: &Stats,
) -> Result<()> {
    let flow_id = stream_id / 4;
    // Build the flow_id varint prefix + context_id zero
    let mut flow_prefix = Vec::with_capacity(HEADROOM);
    {
        let mut tmp = [0u8; 8];
        let mut b = octets::OctetsMut::with_slice(&mut tmp);
        b.put_varint(flow_id).unwrap();
        let len = b.off();
        flow_prefix.extend_from_slice(&tmp[..len]);
    }
    flow_prefix.push(0x00);

    let mut pending_up = Some(first);
    let mut down: Vec<Batch> = (0..io.down_tx.len())
        .map(|_| Batch::from_pool(&io.down_pool))
        .collect();
    let mut seq_diag = std::env::var_os("USQUE_SEQDIAG").map(|_| SeqDiag::new());
    let mut last_io = Instant::now();
    let mut iterations = 0u32;
    // Packets sent since the last one came back, and when the first of them left.
    let mut unanswered = 0u64;
    let mut unanswered_since = Instant::now();
    let mut capsule = [0u8; 512];

    loop {
        if conn.timeout().is_some_and(|t| t.is_zero()) {
            conn.on_timeout();
        }

        // UDP -> QUIC -> TUN writer
        let mut received = 0;
        for _ in 0..RX_ROUNDS {
            let n = rx.recv(udp_fd, BATCH_PKTS);
            for i in 0..n {
                if let Err(e) = conn.recv(rx.pkt_mut(i), recv_info) {
                    log::debug!("quic recv error: {e}");
                }
            }
            received += n;
            if n > 0 && drain_dgrams(conn, flow_id, io, &mut down, stats, seq_diag.as_mut()) > 0 {
                unanswered = 0;
            }
            if n < BATCH_PKTS {
                break;
            }
        }
        for (w, b) in down.iter_mut().enumerate() {
            if !b.pkts.is_empty() {
                let full = std::mem::replace(b, Batch::from_pool(&io.down_pool));
                io.push_down(w, full);
            }
        }

        // Events on the CONNECT-IP request stream. The proxy can end the
        // tunnel there while the QUIC connection stays up; when it does,
        // datagrams are still acknowledged but no longer forwarded.
        if received > 0 {
            loop {
                match h3_conn.poll(conn) {
                    Ok((sid, quiche::h3::Event::Data)) => {
                        // Capsules (address and route updates). Read them so the
                        // stream's flow control keeps moving; we do not act on them.
                        while let Ok(n) = h3_conn.recv_body(conn, sid, &mut capsule) {
                            log::info!(
                                "capsule data on stream {sid}: {n} bytes: {}",
                                hex::encode(&capsule[..n.min(64)])
                            );
                        }
                    }
                    Ok((sid, quiche::h3::Event::Finished)) if sid == stream_id => {
                        bail!("the proxy closed the CONNECT-IP stream");
                    }
                    Ok((sid, quiche::h3::Event::Reset(code))) if sid == stream_id => {
                        bail!("the proxy reset the CONNECT-IP stream (error {code:#x})");
                    }
                    Ok((_, quiche::h3::Event::GoAway)) => {
                        bail!("the proxy sent GOAWAY");
                    }
                    Ok(_) => {}
                    Err(quiche::h3::Error::Done) => break,
                    Err(e) => bail!("HTTP/3 error: {e}"),
                }
            }
        }

        // TUN reader -> QUIC
        let mut up_batches = 0;
        let mut up_pkts = 0;
        while up_pkts < UP_PKTS_PER_ITER {
            let Some(mut b) = pending_up.take().or_else(|| io.up_rx.try_recv().ok()) else {
                break;
            };
            up_pkts += b.pkts.len();
            let queued = send_up_batch(conn, &flow_prefix, io, &mut b, stats);
            if queued > 0 {
                if unanswered == 0 {
                    unanswered_since = Instant::now();
                }
                unanswered += queued;
            }
            let _ = io.up_ret.send(b);
            up_batches += 1;
        }

        // Always flush outgoing QUIC packets
        let sent = flush(conn, tx, udp_fd)?;
        if let Some(d) = seq_diag.as_mut() {
            d.maybe_print(conn);
        }

        if conn.is_closed() {
            return Ok(());
        }
        if unanswered >= NO_RETURN_PACKETS && unanswered_since.elapsed() >= NO_RETURN_TIMEOUT {
            bail!(
                "{unanswered} packets sent and nothing received for {} s; restarting the tunnel",
                unanswered_since.elapsed().as_secs()
            );
        }

        iterations = iterations.wrapping_add(1);
        let busy = received > 0 || up_batches > 0 || sent > 0;
        if !busy || iterations % STATS_EVERY == 0 {
            let qs = conn.stats();
            stats.quic_lost.store(qs.lost as u64, Ordering::Relaxed);
            stats
                .quic_retrans
                .store(qs.retrans as u64, Ordering::Relaxed);
        }
        if busy {
            last_io = Instant::now();
            continue;
        }

        // Nothing to do: sleep until UDP, uplink, or a timer.
        io.waker.waiting.store(true, Ordering::SeqCst);
        pending_up = io.up_rx.try_recv().ok();
        if pending_up.is_some() {
            io.waker.waiting.store(false, Ordering::SeqCst);
            continue;
        }

        let keepalive_due = if keepalive_interval.is_zero() {
            Duration::from_secs(60)
        } else {
            keepalive_interval.saturating_sub(last_io.elapsed())
        };
        let timeout = conn.timeout().unwrap_or(keepalive_due).min(keepalive_due);
        let mut fds = [
            libc::pollfd {
                fd: udp_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: io.waker.efd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: fds is a valid array of two pollfds.
        let r = unsafe { libc::poll(fds.as_mut_ptr(), 2, duration_to_poll_ms(timeout)) };
        io.waker.waiting.store(false, Ordering::SeqCst);
        if r == 0 {
            conn.on_timeout();
            // Idle for a whole keepalive period: make the peer answer, which
            // keeps NAT state alive and proves the path still works.
            if !keepalive_interval.is_zero() && last_io.elapsed() >= keepalive_interval {
                conn.send_ack_eliciting().ok();
                last_io = Instant::now();
            }
        } else if fds[1].revents != 0 {
            io.waker.drain();
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    // ---- parse_datagram tests ----

    fn encode_varint(val: u64) -> Vec<u8> {
        let mut tmp = [0u8; 8];
        let mut b = octets::OctetsMut::with_slice(&mut tmp);
        b.put_varint(val).unwrap();
        let len = b.off();
        tmp[..len].to_vec()
    }

    fn make_datagram(flow_id: u64, context_id: u64, payload: &[u8]) -> Vec<u8> {
        let mut dgram = Vec::new();
        dgram.extend_from_slice(&encode_varint(flow_id));
        dgram.extend_from_slice(&encode_varint(context_id));
        dgram.extend_from_slice(payload);
        dgram
    }

    #[test]
    fn parse_datagram_valid() {
        let payload = b"hello world";
        let dgram = make_datagram(0, 0, payload);
        let result = parse_datagram(&dgram, 0);
        assert_eq!(result, Some(payload.as_ref()));
    }

    #[test]
    fn parse_datagram_flow_id_mismatch() {
        let dgram = make_datagram(1, 0, b"data");
        assert_eq!(parse_datagram(&dgram, 0), None);
    }

    #[test]
    fn parse_datagram_nonzero_context() {
        let dgram = make_datagram(0, 1, b"data");
        assert_eq!(parse_datagram(&dgram, 0), None);
    }

    #[test]
    fn parse_datagram_empty_payload() {
        let dgram = make_datagram(0, 0, b"");
        // Empty payload means off == dgram.len(), should return None
        assert_eq!(parse_datagram(&dgram, 0), None);
    }

    #[test]
    fn parse_datagram_large_flow_id() {
        // flow_id that requires 4-byte varint encoding
        let flow_id = 16384;
        let payload = vec![0xABu8; 1300];
        let dgram = make_datagram(flow_id, 0, &payload);
        let result = parse_datagram(&dgram, flow_id);
        assert_eq!(result, Some(payload.as_ref()));
    }

    #[test]
    fn parse_datagram_truncated() {
        // Just a single byte - can't even decode flow_id
        let dgram = vec![0xFF];
        assert_eq!(parse_datagram(&dgram, 0), None);
    }

    // ---- format_bytes tests ----

    #[test]
    fn format_bytes_values() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(1536), "1.5 KiB");
        assert_eq!(format_bytes(1_048_576), "1.0 MiB");
        assert_eq!(format_bytes(1_073_741_824), "1.0 GiB");
    }

    // ---- format_duration tests ----

    #[test]
    fn format_duration_values() {
        assert_eq!(format_duration(Duration::from_secs(0)), "0s");
        assert_eq!(format_duration(Duration::from_secs(59)), "59s");
        assert_eq!(format_duration(Duration::from_secs(60)), "1m 00s");
        assert_eq!(format_duration(Duration::from_secs(90)), "1m 30s");
        assert_eq!(format_duration(Duration::from_secs(3600)), "1h 00m 00s");
        assert_eq!(format_duration(Duration::from_secs(3661)), "1h 01m 01s");
    }
}
