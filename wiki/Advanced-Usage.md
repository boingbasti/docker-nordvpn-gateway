# Advanced Usage

## 🔹 SOCKS5 Proxy
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
➡️ Clients can connect to `GATEWAY-IP:1080`.

---
## 🔹 HTTP Proxy (Privoxy)
```yaml
  http-proxy:
    image: boingbasti/nordvpn-privoxy:latest
    container_name: nordvpn-privoxy
    network_mode: "service:nordvpn-gateway"
    depends_on:
      - nordvpn-gateway
    restart: unless-stopped
```
➡️ Clients can connect to `GATEWAY-IP:8118`.
