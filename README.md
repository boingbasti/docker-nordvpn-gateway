# NordVPN Gateway Container

A stable, self-healing, and intelligent Docker container that transforms your host into a secure NordVPN gateway. It is designed to serve as a central, fail-safe internet access point for other containers or your entire LAN.

---
## ✨ Core Features

* 🔒 **Secure & Self-Healing**: Uses token authentication (via Docker Secret) and the built-in killswitch. A persistent loop actively monitors the connection, the VPN daemon socket, and external reachability. On failure, it triggers a clean reconnect.
* ⚡ **Smart Server Selection**: `VPN_AUTO_CONNECT=best` pings recommended servers in parallel and connects to the one with the absolute lowest latency.
* 🧠 **Proactive Server Caching**: A background task caches the "best" server. If the connection drops, the container reconnects instantly without a new search.
* 🚀 **Optimized Performance**: Automatically detects the optimal MTU for your connection using a binary ping test to maximize throughput.
* 🧩 **Advanced WireGuard Bypass**: A core integration that allows an external WireGuard server (e.g., `wg-easy`) to route through the VPN *without* the killswitch blocking its handshake.

---
## 🚀 Quick Start: Secure Proxy (No macvlan needed)

This is the simplest way to get started. This example creates a SOCKS5 proxy that routes all traffic through the VPN. It requires **no extra network setup**.

```yaml
version: "3.9"
services:
  vpn:
    image: boingbasti/nordvpn-gateway:latest
    container_name: nordvpn
    cap_add:
      - NET_ADMIN  # Required for iptables, routing, and MTU adjustment
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
    network_mode: "service:vpn" # <-- This attaches it to the vpn container
    depends_on:
      - vpn
    environment:
      - PROXY_PORT=1080
      - ALLOWED_IPS=192.168.1.0/24 # Your LAN subnet
    restart: unless-stopped
```

---
## 🌐 Recommended Setup: LAN Gateway (macvlan)

To use this container as a gateway for your *entire LAN* (or for complex setups like WireGuard), you need to give it its own IP address using `macvlan`.

### 1. Prerequisite: Create the Macvlan Network

You must create a `macvlan` network on your Docker host *before* running the compose file.

**A. Find your host's network interface:**
Run `ip addr` on your Docker host. Look for your primary interface name (e.g., `eth0`, `eno1`, `enp3s0`).

**B. Create the Docker network:**
Run the following command, replacing the **bold** values with your own LAN settings.

```bash
docker network create -d macvlan \
  --subnet=**192.168.1.0/24** \
  --gateway=**192.168.1.1** \
  -o parent=**eth0** \
  vpn_gateway_net
```
* `vpn_gateway_net` is the name we will use in the compose file.

### 2. Docker Compose (Gateway)

Save this as `docker-compose.yml`. The `vpn` container will now act as a gateway at `192.168.1.100`.

```yaml
version: "3.9"
services:
  vpn:
    image: boingbasti/nordvpn-gateway:latest
    container_name: nordvpn
    networks:
      vpn_gateway_net:
        ipv4_address: 192.168.1.100 # Choose a free IP in your LAN
    cap_add:
      - NET_ADMIN
      - NET_RAW    # Required for the 'best server' latency pings
    devices:
      - /dev/net/tun
    volumes:
      - ./nordvpn_token.txt:/run/secrets/nordvpn_token:ro
      - /etc/localtime:/etc/localtime:ro
    environment:
      - VPN_COUNTRY=Germany
      - VPN_AUTO_CONNECT=best
      - KILLSWITCH=on
      - ALLOWLIST_SUBNET=192.168.1.0/24 # IMPORTANT: Your LAN subnet
      - VPN_MTU=auto
    sysctls:
      - net.ipv4.ip_forward=1
    restart: unless-stopped

networks:
  vpn_gateway_net:
    external: true
```

---
## 🔌 Optional Add-ons (service:vpn)

Once you have the `vpn` container running, you can attach other services to it using `network_mode: service:vpn`. They will be fully protected by the VPN and killswitch.

(This can be added to *either* compose file from the examples above).

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

### AdGuard Home (DNS)
```yaml
  adguardhome:
    container_name: nordvpn-adguard
    image: adguard/adguardhome:latest
    network_mode: "service:vpn"
    depends_on:
      - vpn
    volumes:
      - ./adguard-work:/opt/adguardhome/work
      - ./adguard-config:/opt/adguardhome/conf
    cap_add:
      - NET_ADMIN # Required for AdGuard to handle DNS
    restart: unless-stopped
```

---
## 🧩 Advanced Feature: WireGuard Integration

This feature allows a dedicated WireGuard server (e.g., `wg-easy`) to route through the NordVPN gateway, protected by the killswitch while retaining full LAN access.

This setup **requires** the `macvlan` method from the "Recommended Setup" section.

### Example `docker-compose.yml` (Full Stack)

This file includes both the `vpn` gateway and the `wg-easy` server on the `macvlan` network.

```yaml
version: "3.9"
services:
  vpn:
    image: boingbasti/nordvpn-gateway:latest
    container_name: nordvpn
    networks:
      vpn_gateway_net:
        ipv4_address: 192.168.1.100 # Gateway's IP
    cap_add:
      - NET_ADMIN
      - NET_RAW
    devices:
      - /dev/net/tun
    volumes:
      - ./nordvpn_token.txt:/run/secrets/nordvpn_token:ro
      - /etc/localtime:/etc/localtime:ro
    environment:
      # --- Basic VPN Settings ---
      - VPN_COUNTRY=Germany
      - VPN_AUTO_CONNECT=best
      - KILLSWITCH=on
      
      # --- WireGuard Bypass Variables ---
      - WIREGUARD_BYPASS=on
      - WIREGUARD_SERVER_IP=192.168.1.200    # The IP of your wg-easy container
      - WIREGUARD_SUBNET=10.10.10.0/24         # The client network of wg-easy
      
      # --- IMPORTANT: Extend the Allowlist ---
      # Allow your LAN AND your WG clients to use the VPN
      - ALLOWLIST_SUBNET=192.168.1.0/24,10.10.10.0/24
    sysctls:
      - net.ipv4.ip_forward=1
    restart: unless-stopped

  wg-easy:
    image: ghcr.io/wg-easy/wg-easy:15
    container_name: wg-easy-server
    depends_on:
      - vpn
    networks:
      vpn_gateway_net:
        ipv4_address: 192.168.1.200 # Dedicated IP for the WG server
    volumes:
      - ./wg-easy-config:/etc/wireguard
      - /lib/modules:/lib/modules:ro
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    environment:
      - DISABLE_IPV6=true
      - INSECURE=true
      # Note: PostUp/PostDown hooks must be set INSIDE the wg-easy UI
    sysctls:
      - net.ipv4.ip_forward=1
      - net.ipv4.conf.all.src_valid_mark=1
    restart: unless-stopped

networks:
  vpn_gateway_net:
    external: true
```

---
## 📦 Configuration Reference

### 🔑 Authentication
* `NORDVPN_TOKEN`
    * **Required**: (No default). Your login token. Alternatively read from `/run/secrets/nordvpn_token`, which is the preferred method.

### 🌐 Basic Connection
* `VPN_COUNTRY`
    * **Default**: `Germany`
* `VPN_GROUP`
    * **Default**: `p2p`
* `VPN_SERVER`
    * **Default**: (empty)
    * **Note**: If set (e.g., `de1234`), this overrides `VPN_COUNTRY` and `VPN_GROUP`.
* `VPN_TECHNOLOGY`
    * **Default**: `NordLynx`
    * **Options**: `NordLynx` or `OpenVPN`.
* `PROTOCOL`
    * **Default**: (empty)
    * **Dependency**: Only effective if `VPN_TECHNOLOGY=OpenVPN` is set.
    * **Options**: `udp` or `tcp`.

### ⚡ Smart Server Selection
* `VPN_AUTO_CONNECT`
    * **Default**: `off`
    * **Function**: Set to `best` to enable latency-based server optimization.
* `VPN_BEST_SERVER_CHECK_INTERVAL`
    * **Default**: `30`
    * **Dependency**: Only effective if `VPN_AUTO_CONNECT=best`.
    * **Function**: Interval in *minutes* for the background task to find and cache a new best server.

### 🛡️ Network, Gateway & Killswitch
* `KILLSWITCH`
    * **Default**: `on`
    * **Function**: Enables the NordVPN killswitch.
* `POST_QUANTUM`
    * **Default**: `on`
    * **Function**: Enables Post-Quantum encryption.
* `ALLOWLIST_SUBNET`
    * **Default**: (empty)
    * **Function**: **Crucial variable!** Defines which subnets are allowed to route through the VPN (via NAT/MASQUERADE).
    * **Example**: `192.168.1.0/24` (for your LAN) or `192.168.1.0/24,10.10.10.0/24` (for LAN and a Docker network).
* `VPN_MTU`
    * **Default**: `auto`
    * **Function**: `auto` performs automatic MTU detection. You can also set a fixed value (e.g., `1360`).

### 🧩 WireGuard Bypass Integration
* `WIREGUARD_BYPASS`
    * **Default**: `off`
    * **Function**: Set to `on` to enable the special routing and `iptables` rules for the killswitch bypass.
* `WIREGUARD_SERVER_IP`
    * **Default**: (empty)
    * **Dependency**: **REQUIRED** if `WIREGUARD_BYPASS=on`.
    * **Function**: The (macvlan) IP address of your external WireGuard server (e.g., `192.168.1.200`).
* `WIREGUARD_SUBNET`
    * **Default**: (empty)
    * **Dependency**: **REQUIRED** if `WIREGUARD_BYPASS=on`.
    * **Function**: The subnet used by your WireGuard clients (e.g., `10.10.10.0/24`).
* `SHOW_WGHOOKS`
    * **Default**: `off`
    * **Function**: A helper utility. Set to `on` to print the recommended `PostUp`/`PostDown` hooks for `wg-easy` to the log on startup.

### ⚙️ Logging & Maintenance
* `DEBUG`
    * **Default**: `off`
    * **Function**: Set to `on` for extremely verbose logs.
* `CHECK_INTERVAL`
    * **Default**: `60`
    * **Function**: Interval in *seconds* for the "keep-alive" ping check.
* `RETRY_COUNT`
    * **Default**: `2`
    * **Function**: Number of `curl` attempts to verify external connectivity before reconnecting.
* `RETRY_DELAY`
    * **Default**: `2`
    * **Function**: Delay in *seconds* between `curl` attempts.
* `VPN_REFRESH`
    * **Default**: `0`
    * **Function**: Forces a reconnection every X *minutes* (0 = disabled).
* `LOG_STATUS_INTERVAL`
    * **Default**: `0`
    * **Function**: Logs the `nordvpn status` (Uptime, Transfer) every X *minutes* (0 = disabled).
* `CONNECT_TIMEOUT`
    * **Default**: `60`
    * **Function**: Maximum time in *seconds* the `nordvpn connect` command is allowed to run.

---
## 🔍 Troubleshooting

| Problem | Cause | Solution |
| :--- | :--- | :--- |
| Container won't start (network error) | `macvlan` network is missing or misconfigured. | Run the `docker network create` command from the "Prerequisite" step. |
| No internet despite VPN | MTU is too high. | Use `VPN_MTU=auto` or set manually to `1360`. |
| `VPN_AUTO_CONNECT=best` hangs | Missing `NET_RAW` capability. | Add `cap_add: NET_RAW` to the `vpn` service. |
| WG client won't connect (no handshake) | Firewall / Killswitch is blocking. | Set `WIREGUARD_BYPASS=on` and check `WIREGUARD_SERVER_IP`. |
| No LAN access from WG client | Asymmetric routing. | Use the `PostUp` hook (from `SHOW_WGHOOKS`) with MASQUERADE. |

---
## 📎 Links
* 🐳 **Docker Hub**: [boingbasti/nordvpn-gateway](https://hub.docker.com/r/boingbasti/nordvpn-gateway)
* 💻 **GitHub**: [boingbasti/docker-nordvpn-gateway](https://github.com/boingbasti/docker-nordvpn-gateway)
