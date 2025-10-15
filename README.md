# NordVPN Gateway Container
A stable, self-healing Docker container that turns your host into a **NordVPN-based gateway** — featuring a killswitch, automatic MTU detection, smart reconnects, server optimization, and full support for **internal services or external WireGuard servers**.

---
## ✨ Features

- **Secure & Self-Healing**
  - Based on the official NordVPN client (`v4.1.1+`)
  - Token-based authentication (recommended via Docker secret)
  - Built-in killswitch prevents leaks when VPN disconnects
  - Automatic recovery on network or VPN failure

- **Smart Server Selection**
  - `VPN_AUTO_CONNECT=best` finds the fastest server via parallel ping tests
  - Background task periodically re-checks and caches the “Best Server”

- **Performance & Stability**
  - Automatic MTU detection using ping-based testing
  - MSS clamping for optimal TCP performance
  - Active connection checks (`curl` + `ping`) with robust reconnect logic

- **Full Gateway Functionality**
  - NAT / MASQUERADE for LAN or Docker services
  - LAN bypass via `ALLOWLIST_SUBNET`

- **Extensible**
  - Easily attach other containers (e.g., AdGuard, JDownloader, proxies)
  - Full WireGuard integration (via separate macvlan) with active NordVPN killswitch

---
## 🛠 Requirements

- Docker host with:
  - `cap_add: NET_ADMIN` (required)
  - `/dev/net/tun` available
  - (Optional) `cap_add: NET_RAW` for best server auto-detection
- Valid NordVPN token (recommended: `/run/secrets/nordvpn_token`)

---
## 📦 Environment Variables

| Variable | Default | Description |
|:---|:---|:---|
| `VPN_COUNTRY` | `Germany` | Country to connect to |
| `VPN_GROUP` | `p2p` | Server group (`p2p`, `double_vpn`, `obfuscated`, …) |
| `VPN_SERVER` | *(unset)* | Specific server (e.g., `de1234.nordvpn.com`) |
| `VPN_TECHNOLOGY` | `NordLynx` | `NordLynx` or `OpenVPN` |
| `PROTOCOL` | *(unset)* | OpenVPN only: `udp` or `tcp` |
| `VPN_AUTO_CONNECT` | `off` | `best` = automatically finds fastest server |
| `VPN_BEST_SERVER_CHECK_INTERVAL` | `30` | Minutes between best-server checks |
| `KILLSWITCH` | `on` | Enables NordVPN’s built-in killswitch |
| `ALLOWLIST_SUBNET` | *(unset)* | Allowed LAN subnets (e.g., `192.168.179.0/24`) |
| `POST_QUANTUM` | `on` | Enables post-quantum protection |
| `VPN_MTU` | `auto` | MTU autodetect or manual (e.g., `1340`) |
| `VPN_REFRESH` | `0` | Force reconnect after X minutes (`0` = disabled) |
| `CHECK_INTERVAL` | `60` | Interval between connection checks |
| `RETRY_COUNT` | `3` | Retry attempts before reconnect |
| `RETRY_DELAY` | `2` | Delay between retries |
| `CONNECT_TIMEOUT` | `30` | Connection timeout (seconds) |
| `LOG_STATUS_INTERVAL` | `0` | Log VPN status every X minutes (`0` = off) |
| `DEBUG` | `off` | Enable detailed logs |
| `WIREGUARD_BYPASS` | `off` | Allow traffic from external WireGuard server |
| `WIREGUARD_SERVER_IP` | *(unset)* | IP of WireGuard server (e.g., `192.168.179.229`) |
| `WIREGUARD_SUBNET` | *(unset)* | Subnet of WireGuard clients (e.g., `10.10.10.0/24`) |

---
## 🚀 Quick Start (macvlan Gateway)

```yaml
version: "3.9"
services:
  vpn:
    image: boingbasti/nordvpn-gateway:latest
    container_name: nordvpn
    networks:
      macvlan-vpn:
        ipv4_address: 192.168.179.100
    cap_add:
      - NET_ADMIN
      - NET_RAW
    devices:
      - /dev/net/tun
    volumes:
      - ./nordvpn_token.txt:/run/secrets/nordvpn_token:ro
      - /etc/localtime:/etc/localtime:ro
    environment:
      - VPN_COUNTRY=Germany
      - VPN_GROUP=p2p
      - VPN_TECHNOLOGY=NordLynx
      - VPN_AUTO_CONNECT=best
      - VPN_MTU=auto
      - KILLSWITCH=on
      - ALLOWLIST_SUBNET=192.168.179.0/24
    sysctls:
      - net.ipv4.ip_forward=1
    restart: unless-stopped

networks:
  macvlan-vpn:
    external: true
```

---
## 🌐 Optional Add-ons

### SOCKS5 Proxy
```yaml
  socks5:
    image: boingbasti/nordvpn-socks5:latest
    container_name: nordvpn-socks5
    network_mode: "service:vpn"
    depends_on:
      - vpn
    environment:
      - PROXY_PORT=1080
      - ALLOWED_IPS=192.168.179.0/24
    restart: unless-stopped
```

### HTTP Proxy (Privoxy)
```yaml
  http-proxy:
    image: boingbasti/nordvpn-privoxy:latest
    container_name: nordvpn-privoxy
    network_mode: "service:vpn"
    depends_on:
      - vpn
    restart: unless-stopped
```

---
## 🧩 WireGuard Integration (`WIREGUARD_BYPASS`)

This feature allows a **dedicated WireGuard server** (e.g., `wg-easy`)  
to route through the NordVPN gateway — remaining **killswitch-protected**  
while still maintaining full LAN access.

> ⚠️ The WireGuard server **must run in its own macvlan network**.  
> If it shares the same macvlan as the NordVPN container,  
> the NordVPN connection will drop (Linux macvlan limitation).

### Example:
```yaml
  wg-easy:
    image: ghcr.io/wg-easy/wg-easy:15
    container_name: wg-easy-nvpn
    networks:
      macvlan-wg:
        ipv4_address: 192.168.179.229
    volumes:
      - ./wg-easy:/etc/wireguard
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    sysctls:
      - net.ipv4.ip_forward=1
      - net.ipv4.conf.all.src_valid_mark=1
    restart: unless-stopped
```

### Enable in NordVPN Gateway:
```yaml
    environment:
      - WIREGUARD_BYPASS=on
      - WIREGUARD_SERVER_IP=192.168.179.229
      - WIREGUARD_SUBNET=10.10.10.0/24
```

---
## 🔍 Troubleshooting

| Problem | Cause | Solution |
|:--|:--|:--|
| No Internet despite VPN | MTU too high | Set `VPN_MTU=1340` |
| No LAN access | Killswitch active | Add `ALLOWLIST_SUBNET` |
| No WireGuard handshake | Same macvlan | Use separate macvlan for wg-easy |
| `VPN_AUTO_CONNECT=best` hangs | Missing `NET_RAW` | Add `cap_add: NET_RAW` |
| VPN stuck on connect | Token or DNS issue | Check token, restart container |

---
## 🧠 How It Works

1. Container starts NordVPN in NordLynx mode  
2. NAT rules route local traffic through VPN  
3. Healthcheck + keepalive monitor connection  
4. Killswitch enforces VPN-only routing  
5. When `WIREGUARD_BYPASS` is enabled, routing for WireGuard subnet and server IP is allowed  

---
## 📎 Links

- 🐳 **Docker Hub**: [boingbasti/nordvpn-gateway](https://hub.docker.com/r/boingbasti/nordvpn-gateway)  
- 💻 **GitHub**: [boingbasti/docker-nordvpn-gateway](https://github.com/boingbasti/docker-nordvpn-gateway)  
