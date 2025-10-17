# 🛡️ NordVPN Gateway Container

A stable, self-healing, and intelligent Docker container that transforms your host into a secure NordVPN gateway.  
It is designed to serve as a central, fail-safe internet access point for other containers or your entire LAN.

---
## ✨ Core Features

* 🔒 **Secure & Self-Healing** — Uses token authentication (via Docker Secret) and the built-in killswitch.  
  A persistent loop actively monitors the VPN connection, daemon socket, and external reachability.  
  On failure, it triggers a clean reconnect.

* ⚡ **Smart Server Selection** — `VPN_AUTO_CONNECT=best` pings recommended servers in parallel and connects to the one with the lowest latency.

* 🧠 **Proactive Server Caching** — A background task continuously caches the “best” server.  
  If the connection drops, the container reconnects instantly without re-running the full selection process.

* 🚀 **Optimized Performance** — Automatically detects the optimal MTU for your connection using a binary ping test to maximize throughput.

* 🧩 **Advanced WireGuard Bypass** — Allows an external WireGuard server (e.g. `wg-easy`) to route through the VPN *without* the killswitch blocking its handshake.  
  ⚠️ **Note:** WireGuard bypass requires the container to run in a `macvlan` network — it will not work in `network_mode: service:vpn`.

---
## 🚀 Quick Start: Secure Proxy (no macvlan needed)

This is the simplest way to get started. It creates a SOCKS5 proxy that routes all traffic through the VPN — no special network setup required.

```yaml
version: "3.9"
services:
  vpn:
    image: boingbasti/nordvpn-gateway:latest
    container_name: nordvpn
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun
    volumes:
      - ./nordvpn_token.txt:/run/secrets/nordvpn_token:ro
      - /etc/localtime:/etc/localtime:ro
    environment:
      - VPN_TECHNOLOGY=NordLynx
      - VPN_COUNTRY=Germany
      - VPN_AUTO_CONNECT=best
      - KILLSWITCH=on
    restart: unless-stopped

  socks5:
    image: boingbasti/nordvpn-socks5:latest
    container_name: nordvpn-socks5
    network_mode: "service:vpn"
    depends_on:
      - vpn
    environment:
      - PROXY_PORT=1080
      - ALLOWED_IPS=192.168.1.0/24
    restart: unless-stopped
```

---
## 📦 Configuration Reference

### 🔑 Authentication
- **`NORDVPN_TOKEN`** — *(required)*  
  Your NordVPN service token.  
  Preferred method: mount as Docker Secret at `/run/secrets/nordvpn_token`.

### 🌐 Basic Connection
- `VPN_COUNTRY` — default: `Germany`  
- `VPN_GROUP` — default: `p2p`  
- `VPN_SERVER` — specific server (e.g. `de1234`), overrides country/group.  
- `VPN_TECHNOLOGY` — `NordLynx` *(default)* or `OpenVPN`  
- `PROTOCOL` — only effective when using OpenVPN (`udp` or `tcp`)  
- `CONNECT_TIMEOUT` — connection timeout in seconds (default `60`)

### ⚡ Smart Server Selection
- `VPN_AUTO_CONNECT` — set to `best` for latency-based optimization  
- `VPN_BEST_SERVER_CHECK_INTERVAL` — minutes between background best-server updates (default `30`).  
  *(Value in minutes; only active when `VPN_AUTO_CONNECT=best` is set.)*

### 🛡️ Network, Gateway & MTU
- `ALLOWLIST_SUBNET` — subnets allowed to use the VPN (e.g. `192.168.1.0/24,10.10.10.0/24`)  
- `VPN_MTU` — `auto` *(default)* performs automatic MTU detection, or specify fixed value (e.g. `1360`)

### 🧩 WireGuard Bypass Integration
⚠️ **Requires macvlan setup. Not supported in `service:vpn` mode.**

- `WIREGUARD_BYPASS` — *(default: off)* Set to `on` to enable automatic routing rules for an external WireGuard server.  
- `WIREGUARD_SERVER_IP` — WG server IP (e.g. `192.168.1.200`)  
- `WIREGUARD_SUBNET` — subnet of WG clients (e.g. `10.10.10.0/24`)  
- `SHOW_WGHOOKS` — *(default: off)* Set to `on` to print recommended `PostUp`/`PostDown` hooks on startup.

### ⚙️ Security & Encryption
- `KILLSWITCH` — *(default: on)* Set to `off` to disable NordVPN’s built-in killswitch.  
- `POST_QUANTUM` — *(default: on)* Set to `off` to disable post-quantum encryption.  

### 🧠 Logging & Maintenance
- `DEBUG` — *(default: off)* Set to `on` to enable detailed debug logging.  
- `CHECK_INTERVAL` — seconds between health checks (default `60`)  
- `RETRY_COUNT` — retries before reconnect (default `2`)  
- `RETRY_DELAY` — seconds between retries (default `2`)  
- `VPN_REFRESH` — reconnect every X *minutes* (default `0` = disabled)  
- `LOG_STATUS_INTERVAL` — minutes between status logs (default `0` = disabled)

---
## 🔍 Troubleshooting

| Problem | Cause | Solution |
|:---|:---|:---|
| Container won’t start | Missing or misconfigured macvlan network | Run the `docker network create` command above |
| No internet despite VPN | MTU too high | Use `VPN_MTU=auto` or set manually to ~1360 |
| `VPN_AUTO_CONNECT=best` hangs | Missing `NET_RAW` capability | Add `cap_add: NET_RAW` |
| WireGuard client won’t connect | Firewall / killswitch blocking | Set `WIREGUARD_BYPASS=on` and check `WIREGUARD_SERVER_IP` |
| No LAN access from WG clients | Asymmetric routing | Use MASQUERADE in PostUp hook (from `SHOW_WGHOOKS`) |

---
## 📎 Links

- 🐳 **Docker Hub:** [boingbasti/nordvpn-gateway](https://hub.docker.com/r/boingbasti/nordvpn-gateway)  
- 💻 **GitHub:** [boingbasti/docker-nordvpn-gateway](https://github.com/boingbasti/docker-nordvpn-gateway)

---

🧠 **Use Cases**
- Secure LAN Gateway  
- AdGuard / DNS over VPN  
- WireGuard-over-NordVPN setup  
- SOCKS5 and HTTP Proxy over VPN
