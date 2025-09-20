# Environment Variables

The following environment variables control the container's behavior:

| Variable | Default | Description |
| :--- | :--- | :--- |
| `VPN_COUNTRY` | `Germany` | Country to connect to. |
| `VPN_GROUP` | `p2p` | Optional server group (`p2p`, `double_vpn`, `obfuscated`, etc.). |
| `VPN_SERVER` | *(unset)* | Specific server hostname (overrides country/group). |
| `VPN_TECHNOLOGY` | `NordLynx` | `NordLynx` or `OpenVPN`. |
| `PROTOCOL` | *(unset)* | For OpenVPN only (`udp` or `tcp`). |
| `KILLSWITCH` | `on` | Enable/disable NordVPN's killswitch. |
| `POST_QUANTUM` | `on` | Enable post-quantum VPN protection. |
| `ALLOWLIST_SUBNET` | *(unset)* | Subnet allowed through the gateway (e.g., `192.168.1.0/24`). |
| `CHECK_INTERVAL` | `60` | Seconds between connection checks. |
| `RETRY_COUNT` | `2` | Number of retries before reconnect. |
| `RETRY_DELAY` | `2` | Delay between retries. |
| `CONNECT_TIMEOUT` | `60` | Timeout for initial connect. |
| `VPN_MTU` | `auto` | Auto-detect MTU or set manually. |
| `VPN_REFRESH` | `0` | Minutes before forced reconnect (`0` = off). |
| `LOG_STATUS_INTERVAL` | `0` | Interval for logging connection stats. |
| `DEBUG` | `off` | Enable debug logging. |
| `NORDVPN_TOKEN` | *(unset)* | Your token (or Docker secret). |
| `VPN_AUTO_CONNECT` | `off` | Set to `best` for auto best-server selection. |
| `VPN_BEST_SERVER_CHECK_INTERVAL` | `30` | Minutes between background best-server checks. |
