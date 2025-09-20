# Installation & Setup

This page explains how to install and run the NordVPN Gateway container.

---
## 🛠 Requirements
- Docker installed
- Access to `/dev/net/tun`
- `cap_add: NET_ADMIN` capability (and optionally `NET_RAW` for best-server auto detection)
- A valid NordVPN token (recommended via Docker secret)

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
      # - NET_RAW # optional for auto best-server selection
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
    restart: unless-stopped
```

---
## 🌐 macvlan Setup (LAN Gateway)
```yaml
networks:
  macvlan:
    external: true
```

Attach the container to this network to give it a LAN IP.
