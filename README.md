# usque-rs

> **This fork** reworks the data path for small multi-core routers: a threaded
> pipeline with batched UDP I/O, TCP segment merging on TUN writes, BBR2, and a
> keepalive with dead-peer detection. On an RT-AX86U it went from about
> 150 Mbit/s to about 600 Mbit/s.
>
> | Read this | For |
> |---|---|
> | [docs/GUIDE.zh-CN.md](docs/GUIDE.zh-CN.md) | 中文导读：协议、代码地图、一个包的旅程、路由器脚本、踩过的坑、怎么编译和做实验 |
> | [PERFORMANCE.md](PERFORMANCE.md) | Design decisions and measurements |
> | [contrib/asuswrt-merlin](contrib/asuswrt-merlin) | A ready-made service for Asuswrt-Merlin routers: LAN-wide IPv4 through the tunnel, plus native IPv6 when the upstream gateway delegates no prefix |
>
> Everything below is the upstream README.

A tiny Rust rewrite of my previous [usque](https://github.com/Diniboy1123/usque) project. The goal is simple: a decently fast, native tunnel using Cloudflare WARP and its MASQUE-based protocol.

This is just the `nativetun` implementation from the [Go version](https://github.com/Diniboy1123/usque/blob/main/README.md#native-tunnel-mode-for-advanced-users-linux-and-windows-only) and it's **Linux-only**. If you need proxy support or other platforms, this isn't for you. Check the docs over there to understand the project better.

Just like the Go based usque project, this tool also won't try to mess with your routes, you gotta set them up yourself. IP(v4 and v6) address and MTU is configured for you.

Read [SETUP_NOTES.md](SETUP_NOTES.md) for my use-case.

## Why the rewrite?

I wrote the Go version as a PoC research client back when I was mostly focused on proxies. Since then, I’ve moved countries and my local ISP doesn't provide native IPv6. I wanted to use WARP to fill that gap, but there isn't an official client for my platform yet.

Since my router is a literal **hot potato**, I wanted to get this working with zero copies. This project is basically just speedy glue that takes packets from the kernel, translates them to CONNECT-IP, and vice-versa.

## How it differs from the Go version

**usque (Go):**
- Reconnects if it loses the connection.
- Uses a hardcoded initial packet size.

**usque-rs (Rust):**
- Reconnects on-demand.
- Tries to grow the packet size on the fly using protocol-supported PMTU discovery :tm:.

## Is it PQC ready?

**No.** It's not a priority right now. Lattice-based math usually eats more RAM and comes with much larger key sizes—two things I really don't want running on a resource-constrained router.

## Performance

Still needs to be measured properly, but it is able to max out my 150 Mbit/s residential downstream and 30 Mbit/s upstream network on a `Cudy WR3000P v1` with some Mediatek 1.3 GHz Dual-Core Cortex-A53 CPU with a load avg of 0.4 during the speedtest. That is good enough for my goals. And memory usage was optimized for as less copies as possible.

## Disclaimer

Please do NOT use this tool for abuse. At the end of the day you hurt Cloudflare, which is probably unfair as you get this stuff even for free, secondly you will most likely get this tool sanctioned and ruin the fun for everyone.

The tool mimics certain properties of the official clients, those are mostly done for stability and compatibility reasons. I never intended to make this tool indistinguishable from the official clients. That means if they want to detect this tool, they can. I am not responsible for any consequences that may arise from using this tool. That is absolutely your own responsibility. I am not responsible for any damage that may occur to your system or your network. This tool is provided as is without any guarantees. Use at your own risk.

While the tool was made with security considerations in mind, I am not a security expert nor an IT professional. I am just a hobbyist and this is just a hobby project. Again, use at your own risk. However security reports are welcome. Feel free to open an issue with your contact details and I will get back to you, so you can share your findings **IN PRIVATE**. Once there was enough time to fix the issue, I will credit you in the release notes and the findings can be made public. I appreciate any help in making this tool more secure.

**This tool is not affiliated with Cloudflare in any way. The tool was neither endorsed nor reviewed by Cloudflare. It is an independent research project. Cloudflare Warp, Warp+, 1.1.1.1™, Cloudflare Access™, Cloudflare Gateway™ and Cloudflare One™ [are all registered trademarks/wordmarks](https://www.cloudflare.com/trademark/) of Cloudflare, Inc. If you are a Cloudflare employee and you think this project is in any way harmful, please open an issue and I will do my best to contact you and resolve the issue.**
