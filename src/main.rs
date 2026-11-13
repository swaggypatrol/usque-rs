//! usque-rs - MASQUE (CONNECT-IP) client for Cloudflare WARP.

mod config;
mod register;
mod tls;
mod tun_device;
mod tunnel;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "usque-rs",
    about = "Unofficial Cloudflare WARP MASQUE client in Rust"
)]
struct Cli {
    #[arg(short, long, default_value = "config.json")]
    config: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Register a new client and enroll a device key
    Register {
        #[arg(short, long, default_value = "en_US")]
        locale: String,
        #[arg(short, long, default_value = "PC")]
        model: String,
        #[arg(short, long)]
        name: Option<String>,
        #[arg(long)]
        jwt: Option<String>,
        #[arg(short, long, default_value_t = false)]
        accept_tos: bool,
    },
    /// Expose WARP as a native TUN device
    #[command(name = "nativetun")]
    NativeTun {
        #[arg(short = 'P', long, default_value_t = 443)]
        connect_port: u16,
        #[arg(short = '6', long, default_value_t = false)]
        ipv6: bool,
        #[arg(short = 'F', long, default_value_t = false)]
        no_tunnel_ipv4: bool,
        #[arg(short = 'S', long, default_value_t = false)]
        no_tunnel_ipv6: bool,
        #[arg(short, long, default_value = "consumer-masque.cloudflareclient.com")]
        sni_address: String,
        #[arg(short, long, default_value_t = 30)]
        keepalive_period: u64,
        #[arg(short, long, default_value_t = 1280)]
        mtu: u32,
        #[arg(short = 'I', long, default_value_t = false)]
        no_iproute2: bool,
        #[arg(short = 'n', long)]
        interface_name: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Register {
            locale,
            model,
            name,
            jwt,
            accept_tos,
        } => cmd_register(&cli.config, &locale, &model, name, jwt, accept_tos).await,
        Commands::NativeTun {
            connect_port,
            ipv6,
            no_tunnel_ipv4,
            no_tunnel_ipv6,
            sni_address,
            keepalive_period,
            mtu,
            no_iproute2,
            interface_name,
        } => {
            cmd_nativetun(
                &cli.config,
                connect_port,
                ipv6,
                no_tunnel_ipv4,
                no_tunnel_ipv6,
                &sni_address,
                Duration::from_secs(keepalive_period),
                mtu,
                no_iproute2,
                interface_name,
            )
            .await
        }
    }
}

async fn cmd_register(
    config_path: &str,
    locale: &str,
    model: &str,
    device_name: Option<String>,
    jwt: Option<String>,
    accept_tos: bool,
) -> Result<()> {
    if let Ok(existing) = config::Config::load(config_path) {
        let _ = existing;
        eprint!("Config already exists. Overwrite? (y/n): ");
        let mut response = String::new();
        std::io::stdin().read_line(&mut response)?;
        if response.trim() != "y" {
            log::info!("Aborted.");
            return Ok(());
        }
    }

    if !accept_tos {
        eprintln!(
            "You must accept the Terms of Service \
             (https://www.cloudflare.com/application/terms/) to register."
        );
        eprint!("Do you agree? (y/n): ");
        let mut response = String::new();
        std::io::stdin().read_line(&mut response)?;
        if response.trim() != "y" {
            anyhow::bail!("User did not accept TOS");
        }
    }

    log::info!("Registering with locale={locale} model={model}");
    let account_data = register::register(model, locale, jwt.as_deref()).await?;
    log::info!("Registration successful, enrolling device key...");

    let (priv_key_der, pub_key_der) = register::generate_ec_keypair()?;
    let updated = register::enroll_key(&account_data, &pub_key_der, device_name.as_deref()).await?;

    let cfg = config::Config::from_account_data(&updated, &account_data.token, &priv_key_der);
    cfg.save(config_path)?;
    log::info!("Config saved to {config_path}");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn cmd_nativetun(
    config_path: &str,
    connect_port: u16,
    use_ipv6: bool,
    no_tunnel_ipv4: bool,
    no_tunnel_ipv6: bool,
    sni: &str,
    keepalive_period: Duration,
    mtu: u32,
    no_iproute2: bool,
    interface_name: Option<String>,
) -> Result<()> {
    let cfg = config::Config::load(config_path)?;
    eprintln!("Config loaded from {config_path}");

    let endpoint_ip: std::net::IpAddr = if use_ipv6 {
        cfg.endpoint_v6.parse()?
    } else {
        cfg.endpoint_v4.parse()?
    };
    let endpoint = std::net::SocketAddr::new(endpoint_ip, connect_port);

    let tun_cfg = tun_device::TunConfig {
        name: interface_name,
        mtu,
        ipv4: if no_tunnel_ipv4 {
            None
        } else {
            Some(cfg.ipv4.clone())
        },
        ipv6: if no_tunnel_ipv6 {
            None
        } else {
            Some(cfg.ipv6.clone())
        },
        setup_addresses: !no_iproute2,
    };
    let tun_dev = tun_device::create_tun(&tun_cfg)?;

    if no_iproute2 {
        eprintln!("Skipping address setup (--no-iproute2)");
    } else {
        tun_device::configure_tun(&tun_cfg, &tun_dev).await?;
    }

    let tunnel_cfg = tunnel::TunnelConfig {
        endpoint,
        sni: sni.to_string(),
        keepalive_period,
        mtu,
    };

    tokio::task::block_in_place(|| tunnel::maintain_tunnel(&cfg, &tunnel_cfg, &tun_dev))
}
