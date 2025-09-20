# Troubleshooting

## Common Issues

### ❌ `VPN_AUTO_CONNECT=best` fails
The parallel ping test might be blocked.  
✅ Add `NET_RAW` capability in `docker-compose.yml`.

### ❌ Freezes / Slow loading
Usually MTU-related.  
✅ Use `VPN_MTU=auto` or set `VPN_MTU=1340`.

### ❌ Daemon not reachable
Ensure `/dev/net/tun` exists and `NET_ADMIN` is enabled.

### ❌ No VPN interface
Check your token and environment variables.

### ❌ Need debug logs
Run with `DEBUG=on`.
