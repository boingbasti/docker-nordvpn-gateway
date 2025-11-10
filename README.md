# 🛡️ NordVPN Gateway Container

A **stable, self-healing, and intelligent** Docker container that turns your host into a secure **NordVPN gateway** for other containers and your entire LAN.  
It supports **WireGuard server integration**, **DNS over VPN** via AdGuard Home, and **SOCKS5 / HTTP proxies**, all routed through NordVPN.

---

## ✨ Core Features

- 🔒 **Secure & Self-Healing** — Token-based login, NordVPN killswitch, and a resilient control loop that monitors daemon status, connectivity, and reachability. On failure it performs a **clean reconnect** and reapplies routing rules.
- ⚡ **Smart Server Selection** — `VPN_AUTO_CONNECT=best` fetches recommended servers from the NordVPN API, **pings in parallel**, and selects the **lowest-latency** target.
- 🧠 **Proactive Server Caching** — A background task periodically refreshes the current “best” server and stores it in `/tmp/best_server.txt` so reconnects are instant.
- 🚀 **Adaptive MTU Optimization** — Fast **binary-search MTU** detection and TCP MSS clamping keep throughput stable across networks.
- 🧩 **WireGuard Bypass Mode** — Lets a local WireGuard server (e.g. **wg‑easy**) handshake and route through the VPN without the killswitch blocking it. **Requires macvlan** (not supported with `network_mode: service:vpn`).
- 🧱 **Gateway & NAT** — For each CIDR in `ALLOWLIST_SUBNET`, NAT (MASQUERADE) and FORWARD rules are applied automatically; TCPMSS clamping is enabled to avoid fragmentation.
- 🧭 **DNS Stability** — Inside the gateway namespace, NordVPN DNS (`103.86.96.100` / `103.86.99.100`) is enforced to keep dependent services stable and avoid DNS leaks.

---

## 🔐 Authentication (Token)

Two supported methods for the NordVPN token:

| Method | Recommended | Description |
|---|---|---|
| **Docker Secret** mounted at `/run/secrets/nordvpn_token` | **Yes – Recommended** | Secure, persistent, **not** exposed in env or UI. |
| `NORDVPN_TOKEN` environment variable | No – for testing only | Visible in logs/UI; avoid in production. |

**If both are present, the secret is used.**

**Quick setup:**  
```bash
echo "YOUR_NORDVPN_TOKEN_HERE" > ./nordvpn_token.txt
# Do not commit this file
```

Mount in Compose:
```yaml
volumes:
  - ./nordvpn_token.txt:/run/secrets/nordvpn_token:ro
```

---

## 🚀 Quick Start (SOCKS5 proxy, no macvlan required)

```yaml
version: "3.9"
services:
  vpn:
    image: boingbasti/nordvpn-gateway:latest
    container_name: nordvpn
    cap_add: [NET_ADMIN]
    devices: [/dev/net/tun]
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
    depends_on: [vpn]
    environment:
      - PROXY_PORT=1080
      - ALLOWED_IPS=192.168.1.0/24
    restart: unless-stopped
```

---

## 🌐 LAN Gateway (macvlan)

Create the macvlan network **once**:

```bash
docker network create -d macvlan \
  --subnet=192.168.1.0/24 \
  --gateway=192.168.1.1 \
  -o parent=eth0 \
  vpn_gateway_net
```

Minimal gateway service:

```yaml
services:
  vpn:
    image: boingbasti/nordvpn-gateway:latest
    container_name: nordvpn-gateway
    networks:
      vpn_gateway_net:
        ipv4_address: 192.168.1.100   # choose a free IP
    cap_add: [NET_ADMIN, NET_RAW]
    devices: [/dev/net/tun]
    volumes:
      - ./nordvpn_token.txt:/run/secrets/nordvpn_token:ro
      - /etc/localtime:/etc/localtime:ro
    environment:
      - VPN_COUNTRY=Germany
      - VPN_AUTO_CONNECT=best
      - KILLSWITCH=on
      - ALLOWLIST_SUBNET=192.168.1.0/24
      - VPN_MTU=auto
    sysctls:
      - net.ipv4.ip_forward=1
    restart: unless-stopped

networks:
  vpn_gateway_net:
    external: true
```

---

## 🔐 Optional: Secure all DNS with AdGuard Home

Run AdGuard **in the VPN namespace** to ensure **all DNS queries traverse NordVPN** (prevents DNS leaks).

```yaml
adguardhome:
  container_name: nordvpn-adguard
  image: adguard/adguardhome:latest
  depends_on: [vpn]
  network_mode: "service:vpn"
  volumes:
    - ./adguard-work:/opt/adguardhome/work
    - ./adguard-config:/opt/adguardhome/conf
  restart: unless-stopped
```

**Effect:** LAN devices using the gateway and all WireGuard clients get DNS resolution protected by the VPN tunnel.

---

## 🧩 Full Stack Example (Gateway + wg-easy + AdGuard + SOCKS5 + HTTP Proxy)

> Adjust IPs and subnets to your environment. This example reflects a realistic production layout.

```yaml
version: "3.9"

services:

  # 1) NordVPN Gateway (core)
  vpn:
    image: boingbasti/nordvpn-gateway:latest
    container_name: nordvpn
    networks:
      macvlan_net:
        ipv4_address: 192.168.179.100
    stop_grace_period: 45s
    cap_add: [NET_ADMIN, NET_RAW]
    devices: [/dev/net/tun]
    volumes:
      - ./nordvpn_token.txt:/run/secrets/nordvpn_token:ro
      - /etc/localtime:/etc/localtime:ro
    environment:
      # --- Connection & performance ---
      - VPN_TECHNOLOGY=NordLynx
      - VPN_COUNTRY=Germany
      - VPN_GROUP=p2p
      - VPN_AUTO_CONNECT=best
      - VPN_BEST_SERVER_CHECK_INTERVAL=30
      - KILLSWITCH=on
      - POST_QUANTUM=off
      - CONNECT_TIMEOUT=30
      - VPN_MTU=auto
      # Prefer speed-based self-healing over the legacy timer:
      - VPN_SPEED_CHECK_INTERVAL=30      # minutes
      - VPN_MIN_SPEED=20                 # Mbit/s threshold
      - VPN_REFRESH=0                    # legacy timer disabled
      - CHECK_INTERVAL=60
      - RETRY_COUNT=3
      - RETRY_DELAY=2
      - LOG_STATUS_INTERVAL=1440         # minutes
      - DEBUG=off

      # --- Gateway & routing ---
      - ALLOWLIST_SUBNET=192.168.179.0/24,10.10.10.0/24

      # --- WireGuard bypass (macvlan only) ---
      - WIREGUARD_BYPASS=on
      - WIREGUARD_SERVER_IP=192.168.179.229
      - WIREGUARD_SUBNET=10.10.10.0/24
      - SHOW_WGHOOKS=off

    sysctls:
      - net.ipv4.ip_forward=1
      - net.ipv6.conf.all.disable_ipv6=1
      - net.ipv6.conf.default.disable_ipv6=1
    restart: unless-stopped

  # 2) WireGuard server (wg-easy) with its own LAN IP
  wg-easy:
    image: ghcr.io/wg-easy/wg-easy:15
    container_name: nordvpn-wgeasy
    networks:
      macvlan_net:
        ipv4_address: 192.168.179.229
    depends_on: [vpn]
    cap_add: [NET_ADMIN, SYS_MODULE]
    volumes:
      - ./wg-easy-data:/etc/wireguard
      - /lib/modules:/lib/modules:ro
    environment:
      - INSECURE=true
      - DISABLE_IPV6=true
    sysctls:
      - net.ipv6.conf.all.disable_ipv6=1
      - net.ipv6.conf.default.disable_ipv6=1
      - net.ipv6.conf.lo.disable_ipv6=1
    healthcheck:
      test: ["CMD", "ping", "-c", "1", "-W", "5", "1.1.1.1"]
      interval: 60s
      timeout: 10s
      retries: 3
      start_period: 2m
    restart: on-failure

  # 3) AdGuard Home (DNS over VPN)
  adguardhome:
    container_name: nordvpn-adguard
    image: adguard/adguardhome:latest
    depends_on: [vpn]
    network_mode: "service:vpn"
    volumes:
      - ./adguard-work:/opt/adguardhome/work
      - ./adguard-config:/opt/adguardhome/conf
    cap_add: [NET_ADMIN]
    healthcheck:
      test: ["CMD", "nslookup", "google.com", "1.1.1.1"]
      interval: 60s
      timeout: 10s
      retries: 3
      start_period: 2m
    restart: on-failure

  # 4) SOCKS5 proxy (over VPN)
  socks5:
    image: boingbasti/nordvpn-socks5:latest
    container_name: nordvpn-socks5
    depends_on: [vpn]
    network_mode: "service:vpn"
    environment:
      - PROXY_PORT=1080
      - ALLOWED_IPS=192.168.179.0/24,127.0.0.1/32
    healthcheck:
      test: ["CMD", "curl", "-fsSL", "--max-time", "5", "-x", "socks5h://localhost:1080", "https://1.1.1.1"]
      interval: 60s
      timeout: 10s
      retries: 3
      start_period: 1m
    restart: on-failure

  # 5) HTTP proxy (Privoxy over VPN)
  http-proxy:
    image: boingbasti/nordvpn-privoxy:latest
    container_name: nordvpn-privoxy
    depends_on: [vpn]
    network_mode: "service:vpn"
    healthcheck:
      test: ["CMD", "curl", "-fsSL", "--max-time", "5", "-x", "http://localhost:8118", "https://1.1.1.1"]
      interval: 60s
      timeout: 10s
      retries: 3
      start_period: 1m
    restart: on-failure

networks:
  macvlan_net:
    external: true
```

---

## 🧠 Complete Environment Variable Reference

### 1) Basic VPN Connection
| Variable | Default | Options | Example | Description |
|---|---|---|---|---|
| `VPN_COUNTRY` | Germany | Any country | `VPN_COUNTRY=Netherlands` | Select target region. Ignored if server is specified. |
| `VPN_GROUP` | p2p | standard / p2p / double_vpn / onion_over_vpn / obfuscated / dedicated_ip | `VPN_GROUP=standard` | Select NordVPN category. |
| `VPN_SERVER` | (unset) | Server ID or FQDN | `VPN_SERVER=de1234` | Overrides country/group. |
| `VPN_TECHNOLOGY` | NordLynx | NordLynx / OpenVPN | `VPN_TECHNOLOGY=OpenVPN` | Select VPN protocol stack. |
| `PROTOCOL` | (unset) | udp / tcp (OpenVPN only) | `PROTOCOL=udp` | Ignored when using NordLynx. |
| `CONNECT_TIMEOUT` | 60 | Seconds | `CONNECT_TIMEOUT=30` | Timeout used for connect operations. |
| `POST_QUANTUM` | on | on / off | `POST_QUANTUM=off` | Post‑quantum encryption support. |
| `KILLSWITCH` | on | on / off | `KILLSWITCH=on` | Prevents routing leaks. |

### 2) Gateway & Routing
| Variable | Default | Example | Description |
|---|---|---|---|
| `ALLOWLIST_SUBNET` | (unset) | `ALLOWLIST_SUBNET=192.168.1.0/24,10.10.10.0/24` | Subnets allowed to route through VPN. |
| `VPN_MTU` | auto | `VPN_MTU=1360` | Auto binary MTU detection or fixed value. |

### 3) WireGuard Bypass (macvlan only)
| Variable | Default | Example | Description |
|---|---|---|---|
| `WIREGUARD_BYPASS` | off | `WIREGUARD_BYPASS=on` | Enable routing exception for WG handshake. |
| `WIREGUARD_SERVER_IP` | (unset) | `WIREGUARD_SERVER_IP=192.168.179.229` | LAN IP of WireGuard server. |
| `WIREGUARD_SUBNET` | (unset) | `WIREGUARD_SUBNET=10.10.10.0/24` | Client subnet behind wg-easy. |
| `SHOW_WGHOOKS` | off | `SHOW_WGHOOKS=on` | Display suggested PostUp/PostDown hooks. |

### 4) Performance, Health‑Checks & Reconnect
| Variable | Default | Example | Description |
|---|---|---|---|
| `VPN_AUTO_CONNECT` | off | `VPN_AUTO_CONNECT=best` | Select best server by latency. |
| `VPN_BEST_SERVER_CHECK_INTERVAL` | 30 | `VPN_BEST_SERVER_CHECK_INTERVAL=15` | Minutes between best‑server refresh. |
| `VPN_SPEED_CHECK_INTERVAL` | 0 | `VPN_SPEED_CHECK_INTERVAL=30` | Minutes between throughput checks. |
| `VPN_MIN_SPEED` | 5 | `VPN_MIN_SPEED=20` | Minimum Mbit/s before reconnect. |
| `CHECK_INTERVAL` | 60 | `CHECK_INTERVAL=30` | Loop check frequency (seconds). |
| `RETRY_COUNT` | 2 | `RETRY_COUNT=3` | Retry attempts before reconnect. |
| `RETRY_DELAY` | 2 | `RETRY_DELAY=2` | Seconds between retries. |
| `VPN_REFRESH` | 0 | `VPN_REFRESH=1440` | Legacy reconnect timer (use speed check instead). |

### 5) Logging & Diagnostics
| Variable | Default | Example | Description |
|---|---|---|---|
| `LOG_STATUS_INTERVAL` | 0 | `LOG_STATUS_INTERVAL=60` | Minutes between status logs (0=disabled). |
| `DEBUG` | off | `DEBUG=on` | Enable verbose logging. |


## 🔍 Troubleshooting

- **Container won’t start / macvlan errors** → Verify parent interface and recreate network with `-o parent=eth0` adjusted to your host.  
- **Slow speed / drops** → Use `VPN_MTU=auto` or try a manual value around `1360`. Consider enabling `VPN_SPEED_CHECK_INTERVAL` + tuning `VPN_MIN_SPEED`.  
- **`VPN_AUTO_CONNECT=best` hangs** → Add `NET_RAW` capability (needed for ICMP pings).  
- **WG handshake blocked** → Enable `WIREGUARD_BYPASS=on` and verify `WIREGUARD_SERVER_IP` and `WIREGUARD_SUBNET`. View hooks with `SHOW_WGHOOKS=on`.  
- **DNS leaks** → Run AdGuard (or any DNS service) **in the VPN namespace** (`network_mode: "service:vpn"`).

---

## 📎 Links

- Docker Hub: https://hub.docker.com/r/boingbasti/nordvpn-gateway  
- GitHub: https://github.com/boingbasti/docker-nordvpn-gateway

---

## License
MIT