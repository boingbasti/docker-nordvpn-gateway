![GitHub Release](https://img.shields.io/github/v/release/boingbasti/docker-nordvpn-gateway?label=Version&color=blue)
![GitHub Release Date](https://img.shields.io/github/release-date/boingbasti/docker-nordvpn-gateway?label=Last%20Update&color=blue)
![Docker Pulls](https://img.shields.io/docker/pulls/boingbasti/nordvpn-gateway?label=Pulls)
![Image Size](https://img.shields.io/docker/image-size/boingbasti/nordvpn-gateway?label=Image%20Size)

# 🛡️ NordVPN Gateway Container

> ℹ️ **Under the hood:** Based on **NordVPN Linux Client 4.6.0**

A **stable, self-healing, and intelligent** Docker container that turns your host into a secure **NordVPN gateway** for other containers and your entire LAN.
It supports **WireGuard server integration**, **DNS over VPN** via AdGuard Home, and **SOCKS5 / HTTP proxies**, all routed through NordVPN.

---

## ✨ Core Features

* 🔒 **Secure & Self-Healing** — Uses token authentication (via Docker Secret) and the built-in killswitch. A persistent loop monitors the connection and daemon health.
* 🎯 **Quality Ping & Smart Selection** — `VPN_AUTO_CONNECT=best` sends **burst pings (0.2s interval)** to recommended servers. It strictly filters for **0% packet loss** and selects the target with the lowest average latency.
* 🔄 **Smart Candidate Rotation** — If the connected server fails the speed test (latency vs. load mismatch), the container automatically rotates to the next best "candidate" (2nd or 3rd best ping) without getting stuck in a reconnect loop.
* ⚡ **Fail Fast** — Performs an immediate speed check ~15 seconds after connection to ensure the chosen server performs well. If not, it rotates immediately.
* 📈 **Gigabit-Ready Speed Tests** — Optional support for **100MB test files** (`SPEED_TEST_URL`) to accurately measure high-speed lines where TCP slow-start distorts results.
* 🚀 **Adaptive MTU** — Fast **binary-search MTU** detection and TCP MSS clamping keep throughput stable.
* 🧩 **WireGuard Bypass Mode** — Lets a local WireGuard server (e.g. **wg‑easy**) handshake and route through the VPN without the killswitch blocking it. **Requires macvlan**.
* 🧭 **DNS Stability** — Inside the gateway namespace, NordVPN DNS (`103.86.96.100`) is enforced to prevent leaks.

---

## 🔌 Exposed Services & Ports

Since all services share the VPN network stack, they are accessible via the **Gateway IP** (not localhost).

| Service | Port | Description | Usage Example |
|---|---|---|---|
| **SOCKS5 Proxy** | `1080` | Secure proxy for browsers/apps. | `curl -x socks5h://GATEWAY_IP:1080 ipinfo.io` |
| **HTTP Proxy** | `8118` | Privoxy HTTP proxy with ad-blocking. | `curl -x http://GATEWAY_IP:8118 ipinfo.io` |
| **AdGuard Home** | `80` / `3000` | DNS Server & Web Interface. | Open `http://GATEWAY_IP:80` (or `3000` for setup) |
| **WireGuard** | `51820` | UDP Port for VPN Clients (wg-easy). | Configure in Router Port Forwarding. |
| **wg-easy UI** | `51821` | WireGuard Web Admin UI. | Open `http://WG_SERVER_IP:51821` (Note: Has its own IP) |

---

## 🛠 Web-Configurator for Automatic YAML

Instead of manually writing complex YAML, you can use the visual generator:
👉 **[boingbasti/nordvpn-gateway-configurator](https://github.com/boingbasti/docker-nordvpn-gateway-configurator)**

It provides:
✔ UI selection of gateway mode (Simple vs. Advanced)
✔ **Gigabit Support** (100MB Speedtest option)
✔ **Dual Routing Hooks** (LAN Access vs. Strict Isolation)
✔ Automatic calculation of routing rules

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
    depends_on: [vpn]
    environment:
      - PROXY_PORT=1080
      - ALLOWED_IPS=192.168.1.0/24
    restart: unless-stopped

  privoxy:
    image: boingbasti/nordvpn-privoxy:latest
    network_mode: "service:vpn"
    depends_on: [vpn]
    restart: unless-stopped

  adguardhome:
    image: adguard/adguardhome:latest
    network_mode: "service:vpn"
    depends_on: [vpn]
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
| Variable | Default | Description |
|---|---|---|
| `NORDVPN_TOKEN` | *required* | Auth token (use secret mount if possible). |
| `VPN_COUNTRY` | Germany | Target region. |
| `VPN_GROUP` | p2p | Server group. Use `standard` for normal servers. |
| `VPN_SERVER` | (unset) | Specific server (e.g. de1234). Overrides group. |
| `VPN_TECHNOLOGY` | NordLynx | NordLynx or OpenVPN. |
| `PROTOCOL` | (unset) | udp / tcp (OpenVPN only). |
| `CONNECT_TIMEOUT` | 60 | Connection timeout in seconds. |

### 2) Gateway & Routing
| Variable | Default | Example | Description |
|---|---|---|---|
| `ALLOWLIST_SUBNET` | (unset) | `192.168.1.0/24,10.10.10.0/24` | Subnets allowed to route through VPN. |
| `VPN_MTU` | auto | `1360` | Auto binary MTU detection or fixed value. |

### 3) Security & Ad-Blocking
| Variable | Default | Example | Description |
|---|---|---|---|
| `THREAT_PROTECTION_LITE` | off | `on` | Enables DNS-based blocking of ads & threats. |
| `KILLSWITCH` | on | `on` | Drop all non-VPN traffic to prevent leaks. |
| `POST_QUANTUM` | on | `off` | Enable/disable post-quantum encryption support. |

### 4) WireGuard Bypass (macvlan only)
| Variable | Default | Example | Description |
|---|---|---|---|
| `WIREGUARD_BYPASS` | off | `on` | Enable routing exception for WG handshake. |
| `WIREGUARD_SERVER_IP` | (unset) | `192.168.179.229` | LAN IP of WireGuard server. |
| `WIREGUARD_SUBNET` | (unset) | `10.10.10.0/24` | Client subnet behind wg-easy. |
| `SHOW_WGHOOKS` | off | `on` | Display suggested PostUp/PostDown hooks. |

### 5) Performance, Health‑Checks & Reconnect
| Variable | Default | Example | Description |
|---|---|---|---|
| `VPN_AUTO_CONNECT` | off | `best` | Select best server by latency & quality. |
| `VPN_BEST_SERVER_CHECK_INTERVAL` | 30 | `15` | Minutes between best‑server refresh. |
| `VPN_SPEED_CHECK_INTERVAL` | 0 | `60` | Minutes between throughput checks. |
| `VPN_MIN_SPEED` | 5 | `20` | Minimum Mbit/s before rotating to next candidate. |
| `SPEED_TEST_URL` | `http://cachefly.cachefly.net/10mb.test` | `http://cachefly.../100mb.test` | URL for speed tests. Use 100MB file for Gigabit lines. |
| `CHECK_INTERVAL` | 60 | `30` | Loop check frequency (seconds). |
| `RETRY_COUNT` | 2 | `3` | Retry attempts before reconnect. |
| `RETRY_DELAY` | 2 | `2` | Seconds between retries. |
| `VPN_REFRESH` | 0 | `1440` | Forces periodic reconnect to rotate public IP. |

### 6) Logging & Diagnostics
| Variable | Default | Example | Description |
|---|---|---|---|
| `LOG_STATUS_INTERVAL` | 0 | `60` | Minutes between status logs (0=disabled). |
| `DEBUG` | off | `on` | Enable verbose logging. |

---

## 🔍 Troubleshooting

- **Gigabit Speed Issues** → If your line is >250 Mbit, standard speed tests (10MB) are too small. Set `SPEED_TEST_URL` to a 100MB file (e.g., Cachefly or Hetzner) and increase `VPN_SPEED_CHECK_INTERVAL` to `60` min to save traffic.
- **Laggy Connection** → Try `VPN_AUTO_CONNECT=off`. This lets NordVPN load-balancing decide instead of relying purely on ping.
- **Container won’t start / macvlan errors** → Verify parent interface and recreate network with `-o parent=eth0` adjusted to your host.
- **WG handshake blocked** → Enable `WIREGUARD_BYPASS=on` and verify `WIREGUARD_SERVER_IP`.

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
