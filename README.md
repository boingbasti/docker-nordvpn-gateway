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

* 📈 **Performance Self-Healing** — An optional speed test (`VPN_SPEED_CHECK_INTERVAL`) monitors throughput and automatically reconnects if the speed drops below your defined limit (`VPN_MIN_SPEED`), ensuring a fast connection.

* 🧩 **Advanced WireGuard Bypass** — Allows an external WireGuard server (e.g. `wg-easy`) to route through the VPN *without* the killswitch blocking its handshake.
  ⚠️ **Note:** WireGuard bypass requires the container to run in a `macvlan` network — it will not work in `network_mode: service:vpn`.

---

## 🚀 Usage Examples

This project supports multiple use cases. Here are three common setups, from simple to advanced.

### 1. Secure Proxy (Simple)

This is the simplest way to get started. It creates a SOCKS5 proxy that routes all traffic through the VPN — **no special network setup required.**

```yaml
version: "3.9"

services:
  vpn:
    image: boingbasti/nordvpn-gateway:latest
    container_name: nordvpn
    cap_add:
      - NET_ADMIN
      - NET_RAW # Required for 'VPN_AUTO_CONNECT=best' pings
    devices:
      - /dev/net/tun
    volumes:
      - ./nordvpn_token.txt:/run/secrets/nordvpn_token:ro
      - /etc/localtime:/etc/localtime:ro
    environment:
      - VPN_TECHNOLOGY=NordLynx
      - VPN_COUNTRY=Germany
      - VPN_AUTO_CONNECT=best
      - VPN_MTU=auto
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
      # Allow access from your local LAN
      - ALLOWED_IPS=192.168.1.0/24 
    restart: unless-stopped
```

---

### 2. Standalone LAN Gateway (Intermediate)

This setup uses `macvlan` to give the VPN container its own IP address, turning it into a gateway for your LAN. This is the foundation for more complex setups (like in Example 3).

#### Prerequisite: Create the Macvlan Network

You must create a `macvlan` network on your Docker host *before* running the compose file.

**A. Find your host's network interface:**
Run `ip addr` on your Docker host. Look for your primary interface name (e.g., `eth0`, `eno1`).

**B. Create the Docker network:**
Run the following command, replacing the **bold** values with your own LAN settings.

```bash
docker network create -d macvlan   --subnet=**192.168.1.0/24**   --gateway=**192.168.1.1**   -o parent=**eth0**   macvlan_net
```
* `macvlan_net` is the name we will use in the compose file.

#### Docker Compose (Gateway-Only)

This file creates *only* the gateway container at `192.168.1.100`. You can now point other devices in your LAN to this IP as their gateway.

```yaml
version: "3.9"
services:
  vpn:
    image: boingbasti/nordvpn-gateway:latest
    container_name: nordvpn-gateway
    networks:
      macvlan_net:
        # Choose a free IP in your LAN
        ipv4_address: 192.168.1.100
    cap_add:
      - NET_ADMIN
      # Required for 'VPN_AUTO_CONNECT=best' pings
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
      # IMPORTANT: Allow your LAN to use the gateway
      - ALLOWLIST_SUBNET=192.168.1.0/24
      - VPN_MTU=auto
    sysctls:
      # CRITICAL: Enable IP forwarding
      - net.ipv4.ip_forward=1
    restart: unless-stopped

networks:
  macvlan_net:
    external: true
    name: macvlan_net # Must match the name you created
```

---

### 3. Full Gateway Stack (Advanced)

This is the most advanced setup and matches the main `docker-compose.yml` in this repository. It combines the gateway with other services like `wg-easy` and `adguardhome`.

It demonstrates the full architecture:
* **Gateway & WG-Server:** `vpn` and `wg-easy` run on `macvlan` with their own dedicated IPs.
* **Consumer Services:** `adguardhome`, `socks5`, etc., attach directly to the gateway's network using `network_mode: service:vpn`.

#### Prerequisite: Create the Macvlan Network

This setup requires the *same* `macvlan` network from Example 2. If you haven't created it yet, run this command:

```bash
docker network create -d macvlan   --subnet=**192.168.1.0/24**   --gateway=**192.168.1.1**   -o parent=**eth0**   macvlan_net
```

#### Docker Compose (Full Stack)

This is the `docker-compose.yml` file located in the root of this repository.

```yaml
# This docker-compose.yml demonstrates the advanced Gateway-Stack.
# It includes the VPN-Gateway, a WireGuard-Server (wg-easy)
# on the same macvlan, and consumer services (AdGuard, Proxies)
# that use the gateway's network.

version: "3.9"

services:
  # -----------------------------------------------------------------
  #  1. The VPN Gateway (The heart of the stack)
  # -----------------------------------------------------------------
  vpn:
    image: boingbasti/nordvpn-gateway:latest
    container_name: nordvpn-gateway
    networks:
      macvlan_net:
        # Assign a static IP from your LAN (must be free)
        ipv4_address: 192.168.1.100
    stop_grace_period: 45s
    cap_add:
      - NET_ADMIN
      - NET_RAW
    devices:
      - /dev/net/tun
    environment:
      # --- WireGuard Bypass Settings (Example) ---
      - WIREGUARD_BYPASS=on
      - WIREGUARD_SERVER_IP=192.168.1.200 # IP of the wg-easy container
      - WIREGUARD_SUBNET=10.100.100.0/24 # Subnet of your WG clients
      
      # --- Allow LAN and WG clients to use the VPN ---
      - ALLOWLIST_SUBNET=192.168.1.0/24,10.100.100.0/24
      
      # --- Connection & Performance ---
      - VPN_COUNTRY=Germany
      - VPN_AUTO_CONNECT=best
      - VPN_MTU=auto
      - VPN_TECHNOLOGY=NordLynx
      - KILLSWITCH=on

      # --- Maintenance & Resilience ---
      - VPN_REFRESH=0 # Disabled in favor of new Speed Test
      - LOG_STATUS_INTERVAL=60
      - VPN_SPEED_CHECK_INTERVAL=30 # e.g., check every 30 minutes
      - VPN_MIN_SPEED=20 # e.g., reconnect if speed drops below 20 MBit/s
      - DEBUG=off
    volumes:
      - ./nordvpn_token.txt:/run/secrets/nordvpn_token:ro
      - /etc/localtime:/etc/localtime:ro
    sysctls:
      - net.ipv4.ip_forward=1
      - net.ipv6.conf.all.disable_ipv6=1
      - net.ipv6.conf.default.disable_ipv6=1
    restart: unless-stopped

  # -----------------------------------------------------------------
  #  2. WireGuard Server (wg-easy)
  # -----------------------------------------------------------------
  wg-easy:
    image: ghcr.io/wg-easy/wg-easy:latest
    container_name: wireguard-easy
    networks:
      macvlan_net:
        # Assign a static IP from your LAN (must be free)
        ipv4_address: 192.168.1.200
    depends_on:
      - vpn
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    volumes:
      - ./data/wg-easy-config:/etc/wireguard
    environment:
      # Initial setup (Host, DNS, Password, etc.)
      # is now done via the Web UI on first run.
      - DISABLE_IPV6=true
    sysctls:
      - net.ipv6.conf.all.disable_ipv6=1
      - net.ipv6.conf.default.disable_ipv6=1
      - net.ipv6.conf.lo.disable_ipv6=1
    restart: unless-stopped

  # -----------------------------------------------------------------
  #  3. AdGuard Home (Consumer Service)
  # -----------------------------------------------------------------
  adguardhome:
    container_name: adguard-home
    image: adguard/adguardhome:latest
    depends_on: [vpn]
    network_mode: "service:vpn"
    volumes:
      - ./data/adguard-work:/opt/adguardhome/work
      - ./data/adguard-config:/opt/adguardhome/conf
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "nslookup", "google.com", "1.1.1.1"]
      interval: 60s
      timeout: 10s
      retries: 3
      start_period: 2m

  # -----------------------------------------------------------------
  #  4. SOCKS5 Proxy (Consumer Service)
  # -----------------------------------------------------------------
  socks5:
    image: boingbasti/nordvpn-socks5:latest
    container_name: vpn-socks5-proxy
    depends_on: [vpn]
    network_mode: "service:vpn"
    environment:
      - PROXY_PORT=1080
      - ALLOWED_IPS=192.168.1.0/24,127.0.0.1/32
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-fsSL", "--max-time", "5", "-x", "socks5h://localhost:1080", "https://1.1.1.1"]
      interval: 60s
      timeout: 10s
      retries: 3
      start_period: 1m

  # -----------------------------------------------------------------
  #  5. HTTP Proxy (Consumer Service)
  # -----------------------------------------------------------------
  http-proxy:
    image: boingbasti/nordvpn-privoxy:latest
    container_name: vpn-http-proxy
    depends_on: [vpn]
    network_mode: "service:vpn"
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-fsSL", "--max-time", "5", "-x", "http://localhost:8118", "https://1.1.1.1"]
      interval: 60s
      timeout: 10s
      retries: 3
      start_period: 1m

# -----------------------------------------------------------------
#  Network Definition
# -----------------------------------------------------------------
networks:
  macvlan_net:
    # This network must be created *before* starting the stack.
    # (See prerequisite instructions above)
    external: true
    name: macvlan_net # Must match the name you created
```

---
## 📦 Configuration Reference

### 1) Basic VPN Connection
| Variable | Default | Options | Example | Description |
|---|---|---|---|---|
| `VPN_COUNTRY` | Germany | Any country | `VPN_COUNTRY=Netherlands` | Select target region. Ignored if server is specified. |
| `VPN_GROUP` | p2p | standard / p2p / double_vpn / onion_over_vpn / obfuscated / dedicated_ip | `VPN_GROUP=standard` | Select NordVPN category. |
| `VPN_SERVER` | (unset) | Server ID or FQDN | `VPN_SERVER=de1234` | Overrides country/group. |
| `VPN_TECHNOLOGY` | NordLynx | NordLynx / OpenVPN | `VPN_TECHNOLOGY=OpenVPN` | Select VPN protocol stack. |
| `PROTOCOL` | (unset) | udp / tcp (OpenVPN only) | `PROTOCOL=udp` | Ignored when using NordLynx. |
| `CONNECT_TIMEOUT` | 60 | Seconds | `CONNECT_TIMEOUT=30` | Timeout used for connect operations. |

### 2) Gateway & Routing
| Variable | Default | Example | Description |
|---|---|---|---|
| `ALLOWLIST_SUBNET` | (unset) | `ALLOWLIST_SUBNET=192.168.1.0/24,10.10.10.0/24` | Subnets allowed to route through VPN. |
| `VPN_MTU` | auto | `VPN_MTU=1360` | Auto binary MTU detection or fixed value. |

### 3) Security & Ad-Blocking
| Variable | Default | Example | Description |
|---|---|---|---|
| `THREAT_PROTECTION_LITE` | off | `THREAT_PROTECTION_LITE=on` | Enables DNS-based ad/malware blocking. Uses NordVPN's filtered DNS servers. |
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
