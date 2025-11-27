# 🛡️ NordVPN Gateway Container

A **stable, self-healing, and intelligent** Docker container that turns your host into a secure **NordVPN gateway** for other containers and your entire LAN.
It supports **WireGuard server integration**, **DNS over VPN** via AdGuard Home, and **SOCKS5 / HTTP proxies**, all routed through NordVPN.

---

## ✨ Core Features

* 🔒 **Secure & Self-Healing** — Uses token authentication (via Docker Secret) and the built-in killswitch.
  A persistent loop actively monitors the VPN connection, daemon socket, and external reachability.
  On failure, it triggers a clean reconnect.
* ⚡ **Smart Server Selection** — `VPN_AUTO_CONNECT=best` fetches recommended servers from the NordVPN API, **pings in parallel**, and selects the **lowest-latency** target.
* 🧠 **Proactive Server Caching** — A background task periodically refreshes the current “best” server and stores it in `/tmp/best_server.txt` so reconnects are instant.
* 🚀 **Adaptive MTU Optimization** — Fast **binary-search MTU** detection and TCP MSS clamping keep throughput stable across networks.
* 📈 **Performance Self-Healing** — An optional speed test (`VPN_SPEED_CHECK_INTERVAL`) monitors throughput and automatically reconnects if the speed drops below your defined limit (`VPN_MIN_SPEED`).
* 🧩 **WireGuard Bypass Mode** — Lets a local WireGuard server (e.g. **wg‑easy**) handshake and route through the VPN without the killswitch blocking it. **Requires macvlan**.
* 🧱 **Gateway & NAT** — For each CIDR in `ALLOWLIST_SUBNET`, NAT (MASQUERADE) and FORWARD rules are applied automatically.
* 🧭 **DNS Stability** — Inside the gateway namespace, NordVPN DNS (`103.86.96.100`) is enforced to keep dependent services stable and avoid DNS leaks.

---

## 🛠 NEW: Web-Configurator for Automatic YAML

Instead of manually writing complex YAML, you can now use the visual generator:
👉 **[boingbasti/nordvpn-gateway-configurator](https://github.com/boingbasti/docker-nordvpn-gateway-configurator)**

It provides:
✔ UI selection of gateway mode (Simple vs. Advanced)
✔ Automatic calculation of WireGuard routing hooks
✔ Error-free YAML generation

**Run locally:**
```bash
docker run -d \
  --name nordvpn-config-gen \
  -p 8080:80 \
  boingbasti/nordvpn-gateway-configurator:latest
```
Then visit: **[http://localhost:8080](http://localhost:8080)**

---

## 🚀 Usage Examples

### 1. Secure Proxy (Simple)

Creates a SOCKS5 proxy routed fully through the VPN. No special network setup required.

```yaml
version: "3.9"
services:
  vpn:
    image: boingbasti/nordvpn-gateway:latest
    container_name: nordvpn
    cap_add:
      - NET_ADMIN
      - NET_RAW
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

### 2. Standalone LAN Gateway (macvlan)

**1. Create the network once:**
```bash
docker network create -d macvlan \
  --subnet=192.168.1.0/24 \
  --gateway=192.168.1.1 \
  -o parent=eth0 \
  vpn_gateway_net
```

**2. Compose:**
```yaml
services:
  vpn:
    image: boingbasti/nordvpn-gateway:latest
    container_name: nordvpn-gateway
    networks:
      vpn_gateway_net:
        ipv4_address: 192.168.1.100
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

### 3. Full Gateway Stack (Advanced)

Includes: Gateway + WireGuard Server (wg-easy) + AdGuard Home + Proxies.

```yaml
version: "3.9"
services:
  vpn:
    image: boingbasti/nordvpn-gateway:latest
    container_name: nordvpn
    networks:
      vpn_gateway_net:
        ipv4_address: 192.168.1.100
    stop_grace_period: 45s
    cap_add: [NET_ADMIN, NET_RAW]
    devices: [/dev/net/tun]
    volumes:
      - ./nordvpn_token.txt:/run/secrets/nordvpn_token:ro
      - /etc/localtime:/etc/localtime:ro
    environment:
      - VPN_COUNTRY=Germany
      - VPN_AUTO_CONNECT=best
      - KILLSWITCH=on
      - ALLOWLIST_SUBNET=192.168.1.0/24,10.10.10.0/24
      - VPN_MTU=auto
      # WireGuard Bypass
      - WIREGUARD_BYPASS=on
      - WIREGUARD_SERVER_IP=192.168.1.200
      - WIREGUARD_SUBNET=10.10.10.0/24
    sysctls:
      - net.ipv4.ip_forward=1
      - net.ipv6.conf.all.disable_ipv6=1
      - net.ipv6.conf.default.disable_ipv6=1
    restart: unless-stopped

  wg-easy:
    image: ghcr.io/wg-easy/wg-easy:15
    container_name: wg-easy
    networks:
      vpn_gateway_net:
        ipv4_address: 192.168.1.200
    depends_on: [vpn]
    cap_add: [NET_ADMIN, SYS_MODULE]
    volumes:
      - ./wg-easy-config:/etc/wireguard
      - /lib/modules:/lib/modules:ro
    environment:
      - DISABLE_IPV6=true
      - INSECURE=true
    sysctls:
      - net.ipv6.conf.all.disable_ipv6=1
    restart: unless-stopped

  socks5:
    image: boingbasti/nordvpn-socks5:latest
    network_mode: "service:vpn"
    environment:
      - PROXY_PORT=1080
      - ALLOWED_IPS=192.168.1.0/24
    restart: unless-stopped

  privoxy:
    image: boingbasti/nordvpn-privoxy:latest
    network_mode: "service:vpn"
    restart: unless-stopped

  adguardhome:
    image: adguard/adguardhome:latest
    network_mode: "service:vpn"
    volumes:
      - ./adguard-work:/opt/adguardhome/work
      - ./adguard-config:/opt/adguardhome/conf
    restart: unless-stopped

networks:
  vpn_gateway_net:
    external: true
```

---

## ⚙️ Environment Variables

### 1) Basic VPN Connection
| Variable | Default | Options | Example | Description |
|---|---|---|---|---|
| `NORDVPN_TOKEN` | *required* | Auth token (use secret mount if possible). |
| `VPN_COUNTRY` | Germany | Target region. |
| `VPN_GROUP` | p2p | Server group (standard, p2p, double_vpn). |
| `VPN_SERVER` | (unset) | Specific server (e.g. de1234). Overrides group. |
| `VPN_TECHNOLOGY` | NordLynx | NordLynx or OpenVPN. |
| `PROTOCOL` | (unset) | udp / tcp (OpenVPN only). |
| `CONNECT_TIMEOUT` | 60 | Connection timeout in seconds. |

### 2) Gateway & Routing
| Variable | Default | Example | Description |
|---|---|---|---|
| `ALLOWLIST_SUBNET` | (unset) | `ALLOWLIST_SUBNET=192.168.1.0/24,10.10.10.0/24` | Subnets allowed to route through VPN. |
| `VPN_MTU` | auto | `VPN_MTU=1360` | Auto binary MTU detection or fixed value. |

### 3) Security & Ad-Blocking
| Variable | Default | Example | Description |
|---|---|---|---|
| `THREAT_PROTECTION_LITE` | off | `THREAT_PROTECTION_LITE=on` | Enables DNS-based blocking of ads, trackers, and malicious domains. |
| `KILLSWITCH` | on | `KILLSWITCH=on` | Drop all non-VPN traffic to prevent leaks. |
| `POST_QUANTUM` | on | `POST_QUANTUM=off` | Enable/disable post-quantum encryption support. |

### 4) WireGuard Bypass (macvlan only)
| Variable | Default | Example | Description |
|---|---|---|---|
| `WIREGUARD_BYPASS` | off | `WIREGUARD_BYPASS=on` | Enable routing exception for WG handshake. |
| `WIREGUARD_SERVER_IP` | (unset) | `WIREGUARD_SERVER_IP=192.168.179.229` | LAN IP of WireGuard server. |
| `WIREGUARD_SUBNET` | (unset) | `WIREGUARD_SUBNET=10.10.10.0/24` | Client subnet behind wg-easy. |
| `SHOW_WGHOOKS` | off | `SHOW_WGHOOKS=on` | Display suggested PostUp/PostDown hooks. |

### 5) Performance, Health‑Checks & Reconnect
| Variable | Default | Example | Description |
|---|---|---|---|
| `VPN_AUTO_CONNECT` | off | `VPN_AUTO_CONNECT=best` | Select best server by latency. |
| `VPN_BEST_SERVER_CHECK_INTERVAL` | 30 | `VPN_BEST_SERVER_CHECK_INTERVAL=15` | Minutes between best‑server refresh. |
| `VPN_SPEED_CHECK_INTERVAL` | 0 | `VPN_SPEED_CHECK_INTERVAL=30` | Minutes between throughput checks. |
| `VPN_MIN_SPEED` | 5 | `VPN_MIN_SPEED=20` | Minimum Mbit/s before reconnect. |
| `CHECK_INTERVAL` | 60 | `CHECK_INTERVAL=30` | Loop check frequency (seconds). |
| `RETRY_COUNT` | 2 | `RETRY_COUNT=3` | Retry attempts before reconnect. |
| `RETRY_DELAY` | 2 | `RETRY_DELAY=2` | Seconds between retries. |
| `VPN_REFRESH` | 0 | `VPN_REFRESH=1440` | Forces a periodic reconnect to rotate the public exit IP address. Useful for privacy and session/rate-limit resets. If VPN_SPEED_CHECK_INTERVAL is also enabled, whichever triggers first will reconnect. Value is in minutes. |

### 6) Logging & Diagnostics
| Variable | Default | Example | Description |
|---|---|---|---|
| `LOG_STATUS_INTERVAL` | 0 | `LOG_STATUS_INTERVAL=60` | Minutes between status logs (0=disabled). |
| `DEBUG` | off | `DEBUG=on` | Enable verbose logging. |

---

## 🔍 Troubleshooting

- **Container won’t start / macvlan errors** → Verify parent interface and recreate network with `-o parent=eth0` adjusted to your host.
- **Slow speed / drops** → Use `VPN_MTU=auto` or try a manual value around `1360`. Consider enabling `VPN_SPEED_CHECK_INTERVAL` + tuning `VPN_MIN_SPEED`.
- **`VPN_AUTO_CONNECT=best` hangs** → Add `NET_RAW` capability (needed for ICMP pings).
- **WG handshake blocked** → Enable `WIREGUARD_BYPASS=on` and verify `WIREGUARD_SERVER_IP` and `WIREGUARD_SUBNET`. View hooks with `SHOW_WGHOOKS=on`.
- **DNS leaks** → Run AdGuard (or any DNS service) **in the VPN namespace** (`network_mode: "service:vpn"`).

---

## 📎 Links

### Main Gateway Project
* 🐳 **Docker Hub:** [boingbasti/nordvpn-gateway](https://hub.docker.com/r/boingbasti/nordvpn-gateway)
* 💻 **GitHub:** [boingbasti/docker-nordvpn-gateway](https://github.com/boingbasti/docker-nordvpn-gateway)

### Config Generator
* 🐳 **Docker Hub:** [boingbasti/nordvpn-gateway-configurator](https://hub.docker.com/r/boingbasti/nordvpn-gateway-configurator)
* 🎛️ **GitHub:** [boingbasti/docker-nordvpn-gateway-configurator](https://github.com/boingbasti/docker-nordvpn-gateway-configurator)

---

## License
MIT
