# NordVPN Gateway Container

A Docker container that turns your host into a NordVPN-based gateway for your local network or for applications inside Docker.
This image automatically manages a secure VPN connection with killswitch, NAT, MTU optimization, MSS clamping, and automatic reconnects.

---
## ✨ Features
- **Secure Foundation**: Uses the official NordVPN Client (`v4.1.1` or newer) with a secure token login and killswitch enabled by default to prevent leaks.
- **Smart Server Selection**:
  - `VPN_AUTO_CONNECT=best` automatically finds the server with the lowest latency via parallel ping tests.
  - A proactive background process caches the best server periodically, ensuring lightning-fast and killswitch-proof reconnects.
- **Performance & Stability**:
  - Automatically finds the optimal **MTU** with a robust `ping`-based test to prevent connection freezes.
  - A built-in **keep-alive** mechanism (ping and HTTP checks) ensures the connection stays active.
  - Robust reconnect logic handles connection drops gracefully.
- **Full Gateway Functionality**: Provides NAT/MASQUERADE and MSS clamping for all devices on your network.
- **Flexible Connection**: Supports NordLynx/OpenVPN and allows connecting to specific countries, server groups (like P2P), or individual servers.
- **Easy Management**: Includes a Docker Healthcheck for monitoring and a `DEBUG` mode for detailed logs.

---
## 🛠 Requirements
A Docker host with:
- `cap_add: NET_ADMIN` capability (and optionally `NET_RAW` for smart server selection)
- `/dev/net/tun` device access
- A valid NordVPN token (recommended via Docker secret at `/run/secrets/nordvpn_token`)

---
## 📦 Environment Variables
| Variable | Default | Description |
| :--- | :--- | :--- |
| `VPN_COUNTRY` | `Germany` | Country to connect to (e.g., `United_States`). |
| `VPN_GROUP` | `p2p` | **Optional server group.** Use `p2p`, `double_vpn`, `onion_over_vpn`, `obfuscated`, or `dedicated_ip`. |
| `VPN_SERVER` | *(unset)* | **Optional specific server.** Overrides `VPN_COUNTRY` and `VPN_GROUP` (e.g., `de1234.nordvpn.com`). |
| `VPN_TECHNOLOGY` | `NordLynx` | `NordLynx` or `OpenVPN`. |
| `PROTOCOL` | *(unset)* | For OpenVPN only: `udp` or `tcp`. |
| `KILLSWITCH` | `on` | Enable/disable NordVPN's killswitch feature. |
| `POST_QUANTUM` | `on` | Enable post-quantum VPN protection. |
| `ALLOWLIST_SUBNET` | *(unset)* | Subnet that can use the gateway (e.g., `192.168.1.0/24`). |
| `CHECK_INTERVAL` | `60` | Seconds between active connectivity checks. |
| `RETRY_COUNT` | `2` | Number of retries for the connectivity check before triggering a reconnect. |
| `RETRY_DELAY` | `2` | Seconds to wait between retries. |
| `CONNECT_TIMEOUT` | `60` | Max seconds to wait for the `nordvpn connect` command to complete. |
| `VPN_MTU` | `auto` | Set a specific MTU, or `auto` for detection via binary search ping test. |
| `VPN_REFRESH` | `0` | Minutes before a forced reconnect (`0` = disabled). |
| `LOG_STATUS_INTERVAL` | `0` | Minutes between periodic `nordvpn status` logs (`0` = disabled). |
| `DEBUG` | `off` | Set to `on` for detailed logs, including keep-alive ping results. |
| `NORDVPN_TOKEN` | *(unset)* | Your token. Less secure than using a Docker secret. |
| `VPN_AUTO_CONNECT` | `off` | Set to `best` to automatically find the best server on startup. |
| `VPN_BEST_SERVER_CHECK_INTERVAL` | `30` | Minutes between background best-server checks when `VPN_AUTO_CONNECT=best`. |

---
## 🚀 Quick Start (Bridge Mode)
```yaml
version: "3.9"

services:
  nordvpn-gateway:
    image: boingbasti/nordvpn-gateway:latest
    container_name: nordvpn-gateway
    cap_add:
      - NET_ADMIN
      # - NET_RAW # Optional: required on some hosts for best-server auto detection
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
      - POST_QUANTUM=on
    restart: unless-stopped
```

---
## 🌐 Gateway for LAN devices
```yaml
networks:
  macvlan:
    external: true
```

---
## 🔍 Troubleshooting
- **`VPN_AUTO_CONNECT=best` fails or finds no servers**: Add the `NET_RAW` capability.
- **Freezes / slow loading**: Usually an MTU issue. Use `VPN_MTU=auto` or try manual `1340`.
- **Daemon not reachable**: Ensure `/dev/net/tun` exists and `NET_ADMIN` is set.
- **No VPN interface**: Likely connection failure → check token and settings.
- **Detailed logs**: Run with `DEBUG=on`.

---
## 🧩 Optional: Add Proxies inside the VPN
### SOCKS5 Proxy
```yaml
  socks5-proxy:
    image: boingbasti/nordvpn-socks5:latest
    container_name: nordvpn-socks5
    network_mode: "service:nordvpn-gateway"
    depends_on:
      - nordvpn-gateway
    environment:
      - PROXY_PORT=1080
      - ALLOWED_IPS=192.168.1.0/24
    restart: unless-stopped
```

### HTTP Proxy (Privoxy)
```yaml
  http-proxy:
    image: boingbasti/nordvpn-privoxy:latest
    container_name: nordvpn-privoxy
    network_mode: "service:nordvpn-gateway"
    depends_on:
      - nordvpn-gateway
    restart: unless-stopped
```

---
## 🌐 Example: Full `macvlan` Setup with Proxies
```yaml
version: "3.9"

networks:
  lan:
    external: true

services:
  vpn-gateway:
    image: boingbasti/nordvpn-gateway:latest
    container_name: nordvpn-gateway
    cap_add:
      - NET_ADMIN
      # - NET_RAW # Optional: required on some hosts for best-server auto detection
    devices:
      - /dev/net/tun
    networks:
      lan:
        ipv4_address: 192.168.1.240
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
      - ALLOWLIST_SUBNET=192.168.1.0/24
      - CHECK_INTERVAL=60
    restart: unless-stopped

  socks5-proxy:
    image: boingbasti/nordvpn-socks5:latest
    container_name: nordvpn-socks5
    network_mode: "service:vpn-gateway"
    depends_on:
      - vpn-gateway
    environment:
      - PROXY_PORT=1080
      - ALLOWED_IPS=192.168.1.0/24
    restart: unless-stopped

  http-proxy:
    image: boingbasti/nordvpn-privoxy:latest
    container_name: nordvpn-privoxy
    network_mode: "service:vpn-gateway"
    depends_on:
      - vpn-gateway
    restart: unless-stopped
```

---
## 📎 Links
- **Docker Hub**: [boingbasti/nordvpn-gateway](https://hub.docker.com/r/boingbasti/nordvpn-gateway)
- **GitHub**: [boingbasti/docker-nordvpn-gateway](https://github.com/boingbasti/docker-nordvpn-gateway)
