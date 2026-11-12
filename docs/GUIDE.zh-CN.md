# usque-rs 导读（中文）

这份文档带你从头读懂这个 fork：它解决什么问题、一个数据包怎么走完全程、
每个源文件负责什么、路由器上的脚本在做什么，以及怎么自己编译、部署和做实验。

配套的英文文档：

- [`PERFORMANCE.md`](../PERFORMANCE.md)：数据通路的设计取舍和实测数字。
- [`contrib/asuswrt-merlin/README.md`](../contrib/asuswrt-merlin/README.md)：路由器上的安装步骤。
- [`README.md`](../README.md)、[`SETUP_NOTES.md`](../SETUP_NOTES.md)：上游作者的原始说明。

## 1. 它解决什么问题

场景：宽带的 IPv4 很慢（比如要过运营商级 NAT），但原生 IPv6 很快。
做法：在路由器上跑一个 Cloudflare WARP 客户端，把全屋的 IPv4 包进一条走 IPv6 的隧道，
IPv6 流量不进隧道，照常直连。

```
局域网设备 ──► 路由器 ─┬─ IPv4 ─► TUN 网卡 warp0 ─► usque-rs ─► (QUIC, 走 IPv6) ─► Cloudflare ─► 互联网
                      └─ IPv6 ─► 直连上游网关 ─► 互联网
```

上游的 usque-rs 是单线程的，在四核路由器（RT-AX86U）上只能跑到约 150 Mbit/s。
这个 fork 把数据通路改成多线程流水线，同一台路由器上到了约 600 Mbit/s。

## 2. 协议背景：一个包被包了几层

WARP 的新协议叫 MASQUE，本质是「在 HTTP/3 上开一条 IP 隧道」（CONNECT-IP）：

1. 客户端和 Cloudflare 建立一条 QUIC 连接，上面跑 HTTP/3。
2. 客户端发一个扩展 CONNECT 请求（`:protocol = cf-connect-ip`），服务器回 2xx，隧道就通了。
3. 之后每个 IP 包作为一个 QUIC DATAGRAM 帧发送。DATAGRAM 不重传、不保序，
   正适合装 IP 包（重传交给里面的 TCP 自己做）。

一个 IPv4 包在线路上的样子：

```
IPv6 头 | UDP 头 | QUIC 包头 | DATAGRAM 帧 [ 流号 | 上下文号 0 | 原始 IPv4 包 ] | 加密校验
```

- 「流号」等于 CONNECT 请求所在 QUIC 流的编号除以 4，「上下文号」固定是 0。
  两者都是变长整数，通常各占 1 字节。对应代码：`parse_datagram`（拆）和 `forward` 开头的 `flow_prefix`（装）。
- 每个 UDP 载荷最多 1350 字节（`MAX_DATAGRAM_SIZE`），扣掉 QUIC 的开销后，
  隧道网卡的 MTU 取 1280。

## 3. 代码地图

| 文件 | 行数 | 职责 |
|---|---|---|
| `src/main.rs` | 约 230 | 命令行。两个子命令：`register`（注册设备）和 `nativetun`（跑隧道） |
| `src/register.rs` | 约 240 | 调 Cloudflare 的客户端接口注册设备、登记公钥 |
| `src/config.rs` | 约 70 | 读写 `config.json`（私钥、服务器地址、隧道内地址） |
| `src/tls.rs` | 约 70 | 用设备私钥生成自签名客户端证书；校验服务器公钥是否是注册时拿到的那把 |
| `src/tun_device.rs` | 约 160 | 创建 TUN 网卡、配地址和 MTU |
| **`src/tunnel.rs`** | 约 1600 | **数据通路的全部**：三个线程、批处理、QUIC 主循环、保活和断线检测 |
| **`src/gro.rs`** | 约 600 | **TCP 分段合并**：把同一条流的多个小包并成一个大包再交给内核 |
| `src/packet.rs` | 约 360 | 检查 IP 包是否合法；出隧道前把 TTL 减 1 |
| `src/icmp.rs` | 约 350 | 包太大发不出去时，生成「需要分片 / 包太大」的 ICMP 回给发送方 |
| `tests/tunnel_mtu.rs` | 约 600 | 需要 root 的集成测试（真的创建 TUN 网卡） |
| `contrib/asuswrt-merlin/` | | 路由器上的服务脚本，见第 8、9 节 |

要研究性能，重点读 `tunnel.rs` 和 `gro.rs`；其余文件基本是上游原样。

## 4. 启动流程

`usque-rs nativetun ...` 的执行顺序（`main.rs` 的 `cmd_nativetun`）：

1. 读 `config.json`，按 `-6` 选 Cloudflare 的 IPv6 或 IPv4 地址作为连接目标。
2. `tun_device::create_tun`：打开 `/dev/net/tun`（没有就创建设备节点），
   带 `IFF_VNET_HDR` 标志建网卡。这个标志让每个包前面多 10 字节的 `virtio_net_hdr`，
   是后面「合并 TCP 分段」的前提。
3. `tun_device::configure_tun`：给网卡配隧道内的地址和 MTU。
   `-S` 表示不配 IPv6 地址（隧道只走 IPv4），`-F` 相反。
4. `tunnel::maintain_tunnel`：起线程，然后永远循环——
   **空闲时不连接**，等 TUN 网卡上来了第一批包才去握手；会话结束后回到空闲。

`register` 子命令只在第一次用：向 Cloudflare 注册、生成一对 P-256 密钥、
把公钥登记上去（同时声明隧道类型是 masque），结果写进 `config.json`。
加 `--jwt` 是注册到 Zero Trust 组织，不加是普通的免费 WARP。

## 5. 三个线程和一个包的旅程

```
            ┌──────────── 上行（设备 → 互联网）────────────┐
 TUN 网卡 ──► tun-rx 线程 ──[批次队列]──► QUIC 线程 ──► UDP 套接字 ──► Cloudflare
 TUN 网卡 ◄── tun-tx 线程 ◄─[批次队列]─── QUIC 线程 ◄── UDP 套接字 ◄── Cloudflare
            └──────────── 下行（互联网 → 设备）────────────┘
```

| 线程 | 函数 | 做什么 | 默认绑定的 CPU |
|---|---|---|---|
| QUIC 线程 | `forward` | 独占 QUIC 连接：收 UDP、解密、加密、发 UDP | 2 |
| tun-rx | `tun_reader` | 从 TUN 网卡读包 | 3 |
| tun-tx | `tun_writer` | 把解密后的包写进 TUN 网卡（内核的协议栈处理算在这个线程头上） | 3 |

CPU 0 和 1 留给内核收包（见第 8 节的调优）。只有 4 核及以上才绑定，可以用
`USQUE_PIN` 改。不绑定的话，调度器倾向于把互相唤醒的线程叠到同一个核上，实测会损失约四分之一的速度。

### 下行：一个从互联网回来的包

1. `Mmsg::recv`：一次 `recvmmsg` 系统调用最多收 64 个 UDP 包。
2. `conn.recv`：quiche 解密，把里面的 DATAGRAM 放进接收队列。
3. `drain_dgrams`：逐个把 DATAGRAM 拷进当前批次的一个格子里，
   用 `parse_datagram` 去掉前缀、`packet::validate_incoming` 检查合法性。
   批次满 64 个就通过 `Io::push_down` 交给 tun-tx。
4. `tun_writer`：先让 `Gro::plan` 决定哪些包可以合并（第 7 节），再写进 TUN 网卡。
5. 内核把包按路由表转发给局域网设备。

### 上行：一个设备发出的包

1. 内核按策略路由把包送进 TUN 网卡。
2. `tun_reader`：`poll` 等到有包，一口气最多读 64 个；
   `packet::prepare_outgoing` 检查并把 TTL 减 1；整批发给 QUIC 线程；
   如果 QUIC 线程正在睡觉，写一下 eventfd 把它叫醒。
3. `send_up_batch`：在包前面的预留空间里**原地**写上 2 字节前缀，
   调 `conn.dgram_send` 放进 quiche 的发送队列。
   包太大时用 `icmp::compose_icmp_too_large` 回一个 ICMP，让发送方缩小包。
4. `flush`：`conn.send` 生成加密好的 QUIC 包，攒够最多 64 个用一次 `sendmmsg` 发出去。

## 6. `tunnel.rs` 里的几个关键设计

### 批次和内存布局

`Batch` 是一块固定大小的内存，切成 64 个格子（`BATCH_PKTS`），每格 1664 字节（`SLOT`）。
每个包都放在格子里偏移 16 字节（`HEADROOM`）之后的位置，前面留空：

```
格子 i： [ 16 字节预留 ][ IP 包 ........................ ]
          ↑ 上行时在这里原地写 DATAGRAM 前缀；下行时在这里放 virtio 头
```

这样加前缀、加头都不用搬动包本身。批次用完后通过「回收通道」还给产生它的线程，
稳定运行时不再申请内存（quiche 内部除外）。

### 反压，而不是丢包

线程之间的队列是有界的（`QUEUE_BATCHES` = 128 批）。队列满了，上游线程就**阻塞**：

- QUIC 线程忙不过来 → tun-rx 阻塞 → 包在 TUN 网卡的发送队列里排队（队列加长到 5000 个包）。
- tun-tx 忙不过来 → QUIC 线程阻塞 → UDP 包在套接字缓冲区里排队（缓冲区开到 8 MiB）。

开发早期是队列满就丢包，后来改成了阻塞：丢在这里的包已经花过加解密的 CPU，丢了最不划算。

### QUIC 线程的一圈循环（`forward`）

1. QUIC 的定时器到期了就处理（重传、探测等）。
2. **下行**：最多 4 轮 `recvmmsg`（`RX_ROUNDS`），每轮收完立刻 `drain_dgrams`；然后把没满的批次也推给 tun-tx。
3. 收到过包的话，检查 HTTP/3 事件：服务器关闭或重置了 CONNECT 流、发了 GOAWAY，都立即结束会话。
4. **上行**：每圈最多处理 512 个包（`UP_PKTS_PER_ITER`），避免上行把下行饿死。
5. `flush`：把 quiche 想发的包全部发掉（包括 ACK）。
6. 检查连接是否关闭、隧道是否「假活」（见下）。
7. 这一圈有活干就直接进入下一圈；**没活干才睡觉**：同时等 UDP 套接字、eventfd 和定时器。

### 睡觉和叫醒

QUIC 线程睡前把 `Waker::waiting` 置为真，然后**再看一眼**上行队列——
这一眼是为了堵住「tun-rx 刚好在置标志之前放了包、又没写 eventfd」的空档。
tun-rx 每放一批就检查这个标志，为真才写 eventfd。忙的时候两边都不碰 eventfd，省掉系统调用。

### 保活和断线检测

三种机制，分别对付三种死法：

| 情况 | 机制 | 位置 |
|---|---|---|
| 对端没了、网络换了 | 空闲满一个保活周期（默认 30 秒）就发一个要求应答的包；QUIC 空闲超时设为两个周期加 5 秒 | `forward` 末尾的 `send_ack_eliciting`、`run_tunnel_session` 的 `set_max_idle_timeout` |
| 服务器主动结束隧道 | 监听 CONNECT 流的结束、重置和 GOAWAY | `forward` 里的 `h3_conn.poll` |
| **假活**：QUIC 层还在应答，但服务器已经不转发了 | 发出去 32 个以上的包、12 秒内一个都没回来，就重建 | `NO_RETURN_PACKETS`、`NO_RETURN_TIMEOUT` |

「假活」是实测撞到的：局域网里有设备自己又开了一个 WARP，它的隧道套在路由器的隧道里面，
Cloudflare 就停止转发外层隧道，但 QUIC 层照常应答，前两种机制都发现不了。

另外，会话在 2 秒内就失败的话会停 1 秒再试（`MIN_SESSION`），避免网络断开时空转。

### 拥塞控制

隧道自己的 QUIC 包也有拥塞控制。用 CUBIC 时上行卡在 38 Mbit/s（线路能到 145），
而且没有任何丢包报告；换成 BBR2 后是 78–138 Mbit/s。所以默认是 `bbr2`，可用 `USQUE_CC` 改。

DATAGRAM 发送队列限制在 1024 个包（`DGRAM_SEND_QUEUE_LEN`）：拥塞窗口满时包在这里等，
队列太深的话隧道会凭空多出几秒延迟；超出就丢，让里面的 TCP 自己降速。

## 7. `gro.rs`：把小包并成大包

**问题**：每往 TUN 网卡写一个包，内核就要完整走一遍收包流程（路由、防火墙、转发）。
600 Mbit/s 时每秒约 6 万个包，tun-tx 线程成了瓶颈。

**办法**：同一条 TCP 流里连续的分段，头部几乎一样、数据首尾相接。
把它们拼成一个大包，在前面的 `virtio_net_hdr` 里告诉内核「这是个大包，按每段 N 字节切回去」。
内核的收包流程于是每个大包只走一次，真要发给设备时再切开。这和网卡驱动里的 GRO 是同一个思路，
只是在用户态做。实测单条流从约 200 提到约 430 Mbit/s，一次写入通常带 7–15 个分段。

**哪些包能合并**（`parse`、`headers_match`、`Gro::plan`，规则照抄内核的 `tcp_gro_receive`）：

- IPv4、没有 IP 选项、设置了「不分片」、不是分片；TCP 标志只有 ACK，最多再带 PSH。
- 和所在组的第一个包是同一条流，序号正好接上，TCP 头长度相同。
- 除了序号、长度、校验和这些切分时会重新生成的字段，其余头部字段（确认号、窗口、选项……）完全一样。
- 比标准分段短的包、带 PSH 的包只能放在一组的最后。
- **每个分段的 TCP 校验和先验证**。原因：内核切分大包时会重算校验和，
  如果把一个传输中损坏的分段并进去，损坏的数据就会带着「正确」的校验和到达设备。

同一批里最多同时跟踪 16 条流（`MAX_GROUPS`）；一条流里遇到不能合并的包，先把这条流已攒的组写出去，保证顺序不乱。

**怎么写出去**：`merged_header` 生成「virtio 头 + 新的 IP/TCP 头」，
然后 `tun_writer` 用 `writev` 把这个头和各分段的数据区一次写入，数据不用拷贝。
内核拒收的话，退回逐个写原包。

**测试**：`gro.rs` 末尾有 13 个单元测试，其中一类把合并后的大包按内核的规则再切开，
和合并前的包逐字节比较。

用 `USQUE_GRO=0` 可以关掉合并做对比。

## 8. 路由器脚本：`usque.sh`

装在 `/jffs/usque/`，由 `/jffs/scripts/services-start` 在开机时启动。它是一个常驻的看护进程，做六件事：

1. **系统调优**（`tune`）。博通路由器上，不走硬件转发的包要经过一个只有 512 个包的环形缓冲区交给 CPU，
   由内核线程 `bcmsw_rx` 取走。隧道速度下这个线程只要等一下 CPU，缓冲区就溢出，
   而且丢的包 Linux 的计数器看不到。所以把 `bcmsw_rx` 固定在 CPU 0 并给实时优先级，
   再用 RPS 把后续的 IP/UDP 处理分给 CPU 1。
2. **启动隧道**并在它退出后重启（`run`）。
3. **策略路由**（`route_up`）。不改主路由表，而是加规则：

   | 优先级 | 规则 | 作用 |
   |---|---|---|
   | 8980 | 源地址是隧道地址 → 查表 211 | 绑定隧道地址的连接走隧道 |
   | 8990 | 局域网 → 私有地址段、组播、**WARP 入口网段** → 查主表 | 这些目的地不进隧道 |
   | 9000 | 局域网 → 其余全部 → 查表 211 | 表 211 里只有一条默认路由，指向 `warp0` |

   WARP 入口网段留在外面，就是为了防第 6 节说的「隧道套隧道」。
4. **防火墙**（`fw_rules`）。出隧道的流量做地址伪装；TCP 握手时把 MSS 钳到隧道 MTU 以内；
   不允许隧道对面主动连路由器。
5. **自愈**（`ensure`）。固件在 WAN 重连、防火墙重建时会清掉上面的规则，
   所以每 5 秒检查一次，缺了就补。
6. **隧道不通就走直连**（`watch`、`tunnel_ok`）。每 5 秒从隧道地址向两个公网地址发一次 ping。
   只有 ping 通，才保留上表里 8990 和 9000 两组规则；连续两次不通就撤掉，
   局域网的 IPv4 改从 WAN 直接出去，连续两次通了再加回来。
   没有这一条的话，刚开机隧道还没连上、或者隧道断了的时候，IPv4 会被送进一条死隧道，
   表现就是「连得上、上不了网」。实测：隧道死掉后 18 秒切到直连，恢复后 6 秒切回。
   每次切换都清空连接跟踪表和硬件流缓存（`flow_reset`），
   让走旧路径的连接立刻重置、重连，而不是挂着等超时。

## 9. 路由器脚本：`ipv6-bridge.sh`

**问题**：有的上游网关只给一个 /64 的 IPv6 网段，不肯再分一段给下面的路由器（没有前缀下发）。
固件的 Native 模式因此用不了；Passthrough 模式靠转发路由通告和代理邻居发现勉强能用，
但设备在两个网络之间移动后会断，还会把别的设备（如 HomePod）发的特殊通告错误地转发出去。

**办法**：只把 IPv6 在 WAN 口和局域网之间做二层桥接，其它一律不桥接。
局域网设备的 IPv6 就像直接插在上游网关上，IPv4 仍由路由器做 NAT、进隧道。

脚本做的事：

| 部分 | 内容 |
|---|---|
| 过滤规则（`build_nat`、`build_broute`） | 用 ebtables 保证只有 IPv6 帧能过桥；WAN 侧不能通过 IPv6 访问路由器自己的 SSH、DNS、网页端口 |
| 先摘后接（`hold`、`release`） | 见下面「规则会被固件清空」 |
| 路由器自己的 IPv6（`router_v6`） | 固件里 IPv6 设为 Disable，路由器改从桥上通过路由通告拿地址和默认路由 |
| DNS 拦截（`DNS_INTERCEPT=1`） | 上游网关会把自己通告成 IPv6 DNS 服务器。脚本把局域网发往任何服务器的 IPv6 DNS 查询都改由路由器自己应答 |
| 流缓存模式（`flow_l3`） | 博通的硬件加速在默认的「L2 & L3」模式下，对已经见过的一对 MAC 地址直接转发，不再经过 ebtables——只有头几个包会被过滤和拦截。改成「L3」模式后，每条新连接的第一个包都会过一遍规则，速度实测没有差别 |

**规则会被固件清空。** 固件每次重启无线或网络，都会把 ebtables 的所有表清空，
而这正是所有设备重新连接、重新申请地址的时刻。如果这时 WAN 口还挂在桥上，两个局域网就被完全桥在一起（包括 IPv4）：
两边的 DHCP 服务器会互相回应对方的设备，设备可能拿到另一个网络的地址，之后规则恢复，它就彻底不通了。

对策是利用固件的两个钩子：固件执行这类操作**之前**会调用 `/jffs/scripts/service-event` 并等它返回，
脚本在这里先把 WAN 口从桥上摘下来（`hold`）；操作结束后固件调用 `service-event-end`，
脚本重建规则，**然后**才把 WAN 口接回去（`release`）。实测每 0.4 秒采样一次规则状态，
全程没有出现「口在桥上而规则不在」。这两个钩子脚本和 `ipv6-bridge.sh` 必须一起安装。

停用方法见 `contrib/asuswrt-merlin/README.md`：先 `stop`，再去掉脚本的执行权限，否则看护进程几秒内会把它恢复。

## 10. 踩过的坑

每一条都是「现象 → 真正的原因 → 怎么发现的」，是这个项目里最值得看的部分。

| 现象 | 原因 | 怎么定位的 |
|---|---|---|
| 下行有 2–6% 的包莫名丢失，Linux 的计数器全是 0 | 博通的 512 包环形缓冲区溢出 | `USQUE_SEQDIAG=1` 从 TCP 序号的跳变反推丢包，再对照 `bs /b/e cpu/index=host rxq_stat` |
| 上传卡在 38 Mbit/s | CUBIC 在这条线路上停滞 | 换 `USQUE_CC` 逐个对比 |
| 隧道延迟偶尔飙到几秒 | DATAGRAM 发送队列太深 | 看 `[quic] sendq=` 的输出 |
| 「连得上、上不了网」，隧道进程却显示正常 | 局域网设备自己的 WARP 套进了路由器的隧道 | 抓包看到只有 44 字节的应答回来 |
| 重启后隧道不通 | 固件在 WAN 起来后清了策略路由和防火墙规则 | 对比重启前后的 `ip rule` |
| 设备有 IPv6 地址但没有默认路由 | 固件 Passthrough 模式转发了别的设备发的「寿命为 0」的路由通告 | 在路由器上抓路由通告 |
| IPv6 DNS 拦截时灵时不灵 | 硬件加速的 L2 模式绕过了 ebtables | 抓包发现路由器的协议栈根本没看到那些查询，规则计数器也不动 |
| 路由器重启或无线重启后，有的设备「连得上、上不了网」，日志里路由器的 DHCP 回应了上游网络的请求 | 固件清空了 ebtables，而 WAN 口还在桥上，两个局域网被完全桥在一起 | 每 0.4 秒采样规则状态，同时让固件重启无线，看到规则先于桥口消失 |
| 刚开机的头一两分钟 IPv4 不通 | 策略路由已经把流量导进隧道，而隧道还在等 IPv6 就绪 | 隧道日志里开机后先是握手超时、网络不可达，之后才连上 |
| 连路由器的 Windows 电脑开着自己的 WARP 时，每次解析等 12 秒 | 那个客户端把 Wi‑Fi 的 DNS 服务器（含网关的链路本地地址）抄到自己的虚拟网卡上，在那里不通 | 在电脑上抓包，看到邻居请求是从虚拟网卡发出去的 |

## 11. 自己动手

### 编译

在 Linux 或 WSL 里。BoringSSL 需要 cmake、clang、perl、go、nasm（清单见 `.github/workflows/ci.yml`）；
交叉编译用 `cargo-zigbuild`（需要先装 zig）。

```sh
rustup target add aarch64-unknown-linux-musl
cargo install cargo-zigbuild
cargo zigbuild --release --target aarch64-unknown-linux-musl
# 产物：target/aarch64-unknown-linux-musl/release/usque-rs（静态链接，直接拷到路由器）
```

### 测试和检查

```sh
cargo test                                               # 单元测试；tests/ 里的集成测试没有 root 会自动跳过
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings # 和 CI 一致
```

### 部署到路由器

```sh
scp -O target/aarch64-unknown-linux-musl/release/usque-rs admin@router:/jffs/usque/usque-rs.new
ssh admin@router 'cd /jffs/usque && cp -p usque-rs usque-rs.prev && mv usque-rs.new usque-rs && chmod 755 usque-rs && ./usque.sh restart'
```

完整的首次安装步骤在 `contrib/asuswrt-merlin/README.md`。

### 测量

在路由器上直接测隧道本身（不受 Wi‑Fi 影响），把连接绑定到隧道地址：

```sh
A=$(ip -4 addr show dev warp0 | awk '/inet /{sub(/\/.*/,"",$2); print $2}')
curl -4 -s -o /dev/null --max-time 10 --interface "$A" -w '%{speed_download}\n' http://<测速服务器>/<大文件>
```

多条流就同时起多个 `curl`。同时用 `top` 看三个线程各占多少 CPU——哪个线程先到 100%，瓶颈就在哪。

### 可以调的开关

环境变量写在路由器的 `/jffs/usque/env` 里（一行一个），改完 `usque.sh restart`：

| 变量 | 作用 |
|---|---|
| `USQUE_PIN=2,3,3` | 三个数依次是 QUIC 线程、tun-rx、tun-tx 的 CPU；多写几个数就多起几个 tun-tx 线程；`off` 是不绑定 |
| `USQUE_CC=bbr2` | 拥塞控制：`reno`、`cubic`、`bbr`、`bbr2` |
| `USQUE_GRO=0` | 关掉 TCP 分段合并 |
| `USQUE_VNET_HDR=0` | TUN 网卡不带 virtio 头（也就没有合并） |
| `USQUE_STATS=1` | 强制输出每秒一行的实时统计 |
| `USQUE_SEQDIAG=1` | 每 5 秒输出 QUIC 路径统计和从 TCP 序号反推的丢包情况 |
| `ROUTE_LAN=0` | 隧道照常起，但不把局域网流量导进去（方便只在路由器上做测试） |
| `FALLBACK=0` | 隧道不通时也不改走直连（IPv4 会直接断掉） |

代码里的常量集中在 `tunnel.rs` 开头，每个都有注释说明它限制的是什么。

## 12. 还可以继续挖的方向

- QUIC 线程是现在的瓶颈（每个包约 11–13 微秒）。把 `recvmmsg` 挪到第四个线程，大约能再腾出 15%。
- 注册两个设备、开两条连接，把流按哈希分到两条上，QUIC 的处理能力可以翻倍。
- 只合并了 IPv4 的 TCP。IPv6 和 UDP（QUIC 流量）目前是逐包写的。
- 上行方向没有用 TUN 的分段卸载（让内核把大包直接交给用户态），做了的话上行的每包开销也能降。
- 服务器发来的 capsule（地址、路由更新）现在只是读掉并打日志，没有据此调整。
