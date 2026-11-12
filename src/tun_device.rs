use anyhow::{Context, Result};
use std::os::fd::RawFd;

pub struct TunConfig {
    pub name: Option<String>,
    pub mtu: u32,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    #[allow(dead_code)]
    pub setup_addresses: bool,
}

/// An open TUN device (layer 3, no packet-information header).
pub struct TunDev {
    pub fd: RawFd,
    pub name: String,
    /// Every packet read from or written to `fd` is prefixed by a
    /// `virtio_net_hdr`, which lets writes carry merged TCP segments.
    pub vnet_hdr: bool,
}

const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
const IFF_VNET_HDR: libc::c_short = 0x4000;

fn open_tun_node() -> Result<RawFd> {
    const PATH: &[u8] = b"/dev/net/tun\0";
    let open = || {
        // SAFETY: PATH is a valid NUL-terminated string.
        unsafe { libc::open(PATH.as_ptr().cast(), libc::O_RDWR | libc::O_CLOEXEC) }
    };
    let mut fd = open();
    if fd < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
        // Some router firmwares load tun.ko but never create the device node.
        // SAFETY: plain mkdir/mknod calls with valid NUL-terminated paths.
        unsafe {
            libc::mkdir(b"/dev/net\0".as_ptr().cast(), 0o755);
            libc::mknod(
                PATH.as_ptr().cast(),
                libc::S_IFCHR | 0o600,
                libc::makedev(10, 200),
            );
        }
        fd = open();
    }
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to open /dev/net/tun (is the tun kernel module loaded?)");
    }
    Ok(fd)
}

fn attach(fd: RawFd, name: &str, flags: libc::c_short) -> std::io::Result<String> {
    // struct ifreq: 16 bytes of name, then a union whose first member is the flags.
    let mut ifr = [0u8; 40];
    let n = name.len().min(15);
    ifr[..n].copy_from_slice(&name.as_bytes()[..n]);
    ifr[16..18].copy_from_slice(&flags.to_ne_bytes());
    // SAFETY: ifr is a correctly sized, writable ifreq buffer.
    if unsafe { libc::ioctl(fd, TUNSETIFF as _, ifr.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let end = ifr[..16].iter().position(|&b| b == 0).unwrap_or(16);
    Ok(String::from_utf8_lossy(&ifr[..end]).into_owned())
}

pub fn create_tun(cfg: &TunConfig) -> Result<TunDev> {
    let want = cfg.name.as_deref().unwrap_or("tun%d");
    let want_vnet = std::env::var("USQUE_VNET_HDR").map_or(true, |v| v != "0");

    let fd = open_tun_node()?;
    let mut vnet_hdr = want_vnet;
    let mut res = attach(
        fd,
        want,
        IFF_TUN | IFF_NO_PI | if want_vnet { IFF_VNET_HDR } else { 0 },
    );
    if res.is_err() && want_vnet {
        // SAFETY: fd is a valid descriptor we own.
        unsafe { libc::close(fd) };
        let fd2 = open_tun_node()?;
        vnet_hdr = false;
        res = attach(fd2, want, IFF_TUN | IFF_NO_PI);
        let name = res.context("failed to create TUN device")?;
        log::info!("TUN device created: {name} (no vnet_hdr support)");
        return Ok(TunDev {
            fd: fd2,
            name,
            vnet_hdr,
        });
    }
    let name = res.context("failed to create TUN device")?;
    log::info!("TUN device created: {name} (vnet_hdr: {vnet_hdr})");
    Ok(TunDev { fd, name, vnet_hdr })
}

pub async fn configure_tun(cfg: &TunConfig, dev: &TunDev) -> Result<()> {
    use futures::stream::TryStreamExt;

    let tun_name = dev.name.clone();

    let (connection, handle, _) =
        rtnetlink::new_connection().context("failed to create netlink connection")?;
    tokio::spawn(connection);

    let mut links = handle.link().get().match_name(tun_name.clone()).execute();
    let link = links
        .try_next()
        .await
        .context("failed to query link")?
        .context("TUN device not found via netlink")?;
    let link_index = link.header.index;

    handle
        .link()
        .set(link_index)
        .mtu(cfg.mtu)
        .execute()
        .await
        .context("failed to set MTU")?;
    log::info!("MTU set to {}", cfg.mtu);

    if let Some(ref ipv4) = cfg.ipv4 {
        let addr: std::net::Ipv4Addr = ipv4.parse().context("invalid IPv4 address in config")?;
        handle
            .address()
            .add(link_index, std::net::IpAddr::V4(addr), 32)
            .execute()
            .await
            .context("failed to add IPv4 address")?;
        log::info!("IPv4 address {addr}/32 added");
    }

    if let Some(ref ipv6) = cfg.ipv6 {
        let addr: std::net::Ipv6Addr = ipv6.parse().context("invalid IPv6 address in config")?;
        handle
            .address()
            .add(link_index, std::net::IpAddr::V6(addr), 128)
            .execute()
            .await
            .context("failed to add IPv6 address")?;
        log::info!("IPv6 address {addr}/128 added");
    }

    handle
        .link()
        .set(link_index)
        .up()
        .execute()
        .await
        .context("failed to bring link up")?;
    log::info!("Link {tun_name} is UP");

    Ok(())
}
