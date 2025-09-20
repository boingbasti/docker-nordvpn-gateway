# MTU & Stability

Freezes and slow connections are usually MTU-related.

---
## 🔹 Automatic Detection
- `VPN_MTU=auto` uses a binary search `ping` test to detect the optimal MTU.  
- This ensures maximum stability and avoids packet fragmentation.

---
## 🔹 Manual Override
If auto detection fails, set a safe manual value:
- **NordLynx**: `VPN_MTU=1340` (often stable)
- **OpenVPN**: `VPN_MTU=1380`
