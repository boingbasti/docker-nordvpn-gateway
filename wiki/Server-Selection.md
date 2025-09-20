# Server Selection

The container supports flexible server selection.

---
## 🔹 Manual
- Use `VPN_COUNTRY` to connect by country.
- Use `VPN_GROUP` to connect to a group (e.g., `p2p`).
- Use `VPN_SERVER` to connect to a specific server.

---
## 🔹 Automatic (Best Server)
- Set `VPN_AUTO_CONNECT=best`  
- On startup, the container fetches a list of recommended servers from NordVPN's API.  
- It runs parallel pings to find the lowest-latency server.  
- The result is cached and reused for fast reconnects.

---
## 🔹 Background Updates
A background process runs every `VPN_BEST_SERVER_CHECK_INTERVAL` minutes to update the cache.
