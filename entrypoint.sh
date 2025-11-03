#!/bin/bash
set -euo pipefail

# log helper
log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S %Z')] $*" >&2
}

DEBUG=${DEBUG:-off}
debug_log() {
  if [ "$DEBUG" = "on" ]; then
    log "[DEBUG] $*"
  fi
}

# Function to process command output based on debug status
handle_output() {
  if [ "$DEBUG" = "on" ]; then
    while IFS= read -r line; do
      debug_log "NordVPN Client: $line"
    done
  else
    cat > /dev/null
  fi
}


cleanup() {
  log "Signal received, shutting down..."
  
  # Kill background updater if it exists
  if [ -n "${updater_pid-}" ] && ps -p "$updater_pid" > /dev/null; then
    log "Stopping background server updater (PID: $updater_pid)..."
    kill "$updater_pid"
  fi
  
  # Cleanup iptables
  IFACE=$(find_vpn_iface)
  if [ -n "$IFACE" ]; then
    log "Cleaning up iptables rules before exit..."
    cleanup_iptables "$IFACE"
  fi

  log "Disconnecting from NordVPN..."
  nordvpn disconnect &> /dev/null || true

  # --- ROBUSTER DAEMON STOP ---
  log "Stopping NordVPN service daemon (nordvpnd)..."
  
  # 1. Versuche es hÃ¶flich mit dem Service-Befehl
  service nordvpn stop &> /dev/null || true
  sleep 2

  # 2. PrÃ¼fe, ob der Prozess noch lÃ¤uft
  if pgrep -x "nordvpnd" > /dev/null; then
    log "Daemon is still running. Sending SIGTERM..."
    # 3. Sende SIGTERM (hÃ¶fliches Beenden) an den Prozess
    pkill -TERM nordvpnd || true
    sleep 3
  fi

  # 4. Letzte PrÃ¼fung
  if pgrep -x "nordvpnd" > /dev/null; then
    log "Daemon did not respond to SIGTERM. Sending SIGKILL (force)..."
    # 5. Sende SIGKILL (brutales Beenden)
    pkill -9 nordvpnd || true
    sleep 1
  fi
  
  log "NordVPN daemon stopped."
  # --- ENDE ROBUSTER STOP ---

  log "Cleanup complete. Exiting."
  exit 0
}
trap cleanup SIGTERM SIGINT

# --- Token handling ---
if [ -n "${NORDVPN_TOKEN:-}" ]; then
  log "Using NordVPN token from environment variable"
  TOKEN="$NORDVPN_TOKEN"
elif [ -s /run/secrets/nordvpn_token ]; then
  log "Using NordVPN token from secret file"
  TOKEN=$(tr -d '\n' < /run/secrets/nordvpn_token)
else
  log "ERROR: No NordVPN token provided (neither env var nor secret file)"
  exit 1
fi

# Defaults
VPN_BEST_SERVER_CHECK_INTERVAL=${VPN_BEST_SERVER_CHECK_INTERVAL:-30}
CHECK_INTERVAL=${CHECK_INTERVAL:-60}
RETRY_COUNT=${RETRY_COUNT:-2}
RETRY_DELAY=${RETRY_DELAY:-2}
VPN_MTU=${VPN_MTU:-auto}
VPN_REFRESH=${VPN_REFRESH:-0}
ALLOWLIST_SUBNET=${ALLOWLIST_SUBNET:-}
VPN_TECHNOLOGY=${VPN_TECHNOLOGY:-NordLynx}
PROTOCOL=${PROTOCOL:-}
KILLSWITCH=${KILLSWITCH:-on}
POST_QUANTUM=${POST_QUANTUM:-on}
VPN_COUNTRY=${VPN_COUNTRY:-Germany}
VPN_SERVER=${VPN_SERVER:-}
VPN_GROUP=${VPN_GROUP:-p2p}
LOG_STATUS_INTERVAL=${LOG_STATUS_INTERVAL:-0}
CONNECT_TIMEOUT=${CONNECT_TIMEOUT:-60}
VPN_AUTO_CONNECT=${VPN_AUTO_CONNECT:-off}
# New Defaults for WireGuard Support
WIREGUARD_BYPASS=${WIREGUARD_BYPASS:-off}
WIREGUARD_SERVER_IP=${WIREGUARD_SERVER_IP:-}
WIREGUARD_SUBNET=${WIREGUARD_SUBNET:-}
# New Defaults for logging hooks
SHOW_WGHOOKS=${SHOW_WGHOOKS:-off}


# MTU cache
MTU_CACHE=""
BEST_SERVER_CACHE_FILE="/tmp/best_server.txt"

# --- NEW FUNCTION: Determine MTU via Ping Test ---
find_best_mtu() {
  local TARGET_HOST="1.1.1.1"
  local LOWER_BOUND=1300
  local UPPER_BOUND=1500
  local ICMP_HEADER_SIZE=28

  log "Starting fast MTU detection (binary search)..."

  local best_payload_size=0
  local low=${LOWER_BOUND}
  local high=${UPPER_BOUND}

  while [ ${low} -le ${high} ]; do
    mid=$(( (low + high) / 2 ))

    if ping -c 1 -W 1 -M do -s ${mid} ${TARGET_HOST} &> /dev/null; then
      debug_log "MTU Check: Payload of ${mid} bytes is OK."
      best_payload_size=${mid}
      low=$(( mid + 1 ))
    else
      debug_log "MTU Check: Payload of ${mid} bytes is too large."
      high=$(( mid - 1 ))
    fi
  done

  if [ ${best_payload_size} -gt 0 ]; then
    local raw_network_mtu=$(( best_payload_size + ICMP_HEADER_SIZE ))
    local final_vpn_mtu

    if [ "${VPN_TECHNOLOGY,,}" = "openvpn" ]; then
      final_vpn_mtu=$(( raw_network_mtu - 100 ))
    else # Default to NordLynx
      final_vpn_mtu=$(( raw_network_mtu - 80 ))
    fi

    log "MTU detection complete. Optimal Network MTU: ${raw_network_mtu}. Recommended VPN MTU: ${final_vpn_mtu}"
    echo "${final_vpn_mtu}"
  else
    log "WARNING: 'ping' based MTU detection failed. Falling back to a safe default."
    echo "1300" # Fallback value
  fi
}


# --- Helpers ---
find_vpn_iface() { ip -o link show | awk -F': ' '{print $2}' | grep -E "nordlynx|nordtun" | head -n1 || true; }

# ==========================================================
# ===== CORRECTED IPTABLES HELPERS =========================
# ==========================================================
apply_iptables() {
  local IFACE="$1"
  if [ -z "$IFACE" ]; then return; fi
  log "Applying iptables rules (iface=$IFACE)..."
  # Iterate through comma-separated subnets
  for subnet in ${ALLOWLIST_SUBNET//,/ }; do
    # CHANGED log to debug_log
    debug_log "--> Allowing FORWARD and MASQUERADE for subnet: ${subnet}"
    # -C checks if the rule exists, || only adds it if -C fails. Makes the script robust against restarts.
    iptables -t nat -C POSTROUTING -s "${subnet}" -o "$IFACE" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s "${subnet}" -o "$IFACE" -j MASQUERADE
    iptables -C FORWARD -s "${subnet}" -j ACCEPT 2>/dev/null || iptables -A FORWARD -s "${subnet}" -j ACCEPT
    iptables -C FORWARD -d "${subnet}" -j ACCEPT 2>/dev/null || iptables -A FORWARD -d "${subnet}" -j ACCEPT
  done
  iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
}

cleanup_iptables() {
  local IFACE="$1"
  if [ -z "$IFACE" ]; then return; fi
  log "Cleaning up iptables rules..."
  # Iterate through comma-separated subnets
  for subnet in ${ALLOWLIST_SUBNET//,/ }; do
    iptables -t nat -D POSTROUTING -s "${subnet}" -o "$IFACE" -j MASQUERADE 2>/dev/null || true
    iptables -D FORWARD -s "${subnet}" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -d "${subnet}" -j ACCEPT 2>/dev/null || true
  done
  iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
}
# ==========================================================
# ===== END OF CORRECTIONS =================================
# ==========================================================

apply_mtu() { IFACE="$1"; MTU_VAL="$2"; if [ -n "$IFACE" ] && [[ "$MTU_VAL" =~ ^[0-9]+$ ]]; then log "Setting MTU $MTU_VAL on $IFACE..."; ip link set dev "$IFACE" mtu "$MTU_VAL" || true; fi; }

# --- REVISED FUNCTION: Determine MTU ---
detect_mtu_for_iface() {
  IFACE="$1"
  if [ -z "$IFACE" ]; then echo ""; return; fi
  if [ "$VPN_MTU" != "auto" ] && [ -n "${VPN_MTU}" ]; then log "Using configured MTU: ${VPN_MTU}"; echo "${VPN_MTU}"; return; fi
  if [ -n "$MTU_CACHE" ]; then log "Reusing cached MTU value: $MTU_CACHE"; echo "$MTU_CACHE"; return; fi

  DETECTED_MTU=$(find_best_mtu)
  MTU_CACHE="$DETECTED_MTU"
  echo "$DETECTED_MTU"
}

find_best_server() {
  export LC_NUMERIC="C"

  debug_log "Fetching country ID for '${VPN_COUNTRY}'..."
  local country_id
  country_id=$(curl -s 'https://api.nordvpn.com/v1/countries' | jq --arg COUNTRY "$VPN_COUNTRY" '.[] | select(.name == $COUNTRY) | .id')
  if [[ -z "$country_id" ]]; then log "Error: Could not find country ID for '${VPN_COUNTRY}'."; return 1; fi
  debug_log "Found country ID: ${country_id}"

  local api_group_identifier
  case "${VPN_GROUP}" in
    "p2p") api_group_identifier="legacy_p2p" ;;
    "double_vpn") api_group_identifier="legacy_double_vpn" ;;
    "onion_over_vpn") api_group_identifier="legacy_onion_over_vpn" ;;
    "obfuscated") api_group_identifier="legacy_obfuscated_servers" ;;
    "dedicated_ip") api_group_identifier="legacy_dedicated_ip" ;;
    *) api_group_identifier="${VPN_GROUP}" ;;
  esac

  debug_log "Fetching group ID for '${VPN_GROUP}' (using API identifier '${api_group_identifier}')..."
  local group_id
  group_id=$(curl -s 'https://api.nordvpn.com/v1/servers/groups' | jq --arg GROUP "$api_group_identifier" '.[] | select(.identifier == $GROUP) | .id')
  if [[ -z "$group_id" ]]; then log "Error: Could not find group ID for '${VPN_GROUP}'."; return 1; fi
  debug_log "Found group ID: ${group_id}"

  debug_log "--> Step 1: Fetching recommended servers from NordVPN API..."
  local server_list
  server_list=$(curl -s -g "https://api.nordvpn.com/v1/servers/recommendations?filters\[country_id\]=${country_id}&filters\[servers_groups\]\[id\]=${group_id}&limit=15" | \
    jq -r '.[].hostname')

  if [[ -z "$server_list" ]]; then log "Error: No recommended servers found."; return 1; fi

  debug_log "--> Step 2: Pinging recommended servers in parallel to find best latency..."
  local ping_results
  ping_results=$(
    for server in $server_list; do
      (
        local ping_output
        ping_output=$(ping -c 1 -W 2 "$server")
        if [ $? -eq 0 ]; then
          local latency
          latency=$(echo "$ping_output" | tail -n 1 | awk -F'/' '{print $5}')
          if [ -n "$latency" ]; then
            printf "%.2f %s\n" "$latency" "$server"
          fi
        fi
      ) &
    done
    wait
  )

  if [ -z "$ping_results" ]; then log "Error: Parallel ping could not find any responsive servers."; return 1; fi

  local best_server_hostname
  best_server_hostname=$(echo "$ping_results" | sort -n | head -n 1 | awk '{print $2}')

  echo "$best_server_hostname" | sed -E 's/\.nordvpn\.com//'
}

# --- Background process to periodically find the best server ---
background_best_server_updater() {
  debug_log "Starting background process for proactive best-server checks."
  while true; do
    sleep $(( VPN_BEST_SERVER_CHECK_INTERVAL * 60 ))
    debug_log "[BG] Running periodic best-server check..."
    local best_server
    best_server=$(find_best_server || echo "")
    if [ -n "$best_server" ]; then
      debug_log "[BG] Found new best server: ${best_server}. Caching for next reconnect."
      echo "$best_server" > "$BEST_SERVER_CACHE_FILE"
    else
      debug_log "[BG] WARNING: Periodic best-server check failed to find a server."
    fi
  done
}

# --- Startup ---
log "Starting NordVPN container..."
CLIENT_VERSION=$(nordvpn --version 2>/dev/null || echo "unknown")
log "NordVPN client version: $CLIENT_VERSION"

if [[ "$VPN_SERVER" == *".nordvpn.com"* ]]; then log "Full hostname provided in VPN_SERVER. Converting to server ID..."; VPN_SERVER=$(echo "$VPN_SERVER" | sed -E 's/\.nordvpn\.com//'); log "Using server ID: $VPN_SERVER"; fi

if [[ "${VPN_AUTO_CONNECT}" == "best" && -z "${VPN_SERVER}" ]]; then
  log "Auto-finding best server (this may take a few seconds)..."
  best_server_found=$(find_best_server || echo "")
  if [[ -n "$best_server_found" ]]; then
    log "Best server found: ${best_server_found}. This server ID will be used for connection."
    VPN_SERVER="$best_server_found"
    # Prime the cache file with the initial best server
    echo "$best_server_found" > "$BEST_SERVER_CACHE_FILE"
  else
    log "WARNING: Could not find a 'best' server. Using default connection method."
  fi
fi

# ==========================================================
# ===== ROBUST DAEMON START BLOCK ==========================
# ==========================================================
service nordvpn start || true
sleep 2
# CHANGED log to debug_log
debug_log "Waiting for daemon socket file..."
for i in {1..15}; do [ -S /run/nordvpn/nordvpnd.sock ] && break; sleep 1; done

if ! [ -S /run/nordvpn/nordvpnd.sock ]; then
  log "ERROR: Daemon socket file (/run/nordvpn/nordvpnd.sock) did not appear after 15 seconds."
  [ -f /var/log/nordvpn/daemon.log ] && log "Daemon Log:" && tail /var/log/nordvpn/daemon.log
  exit 1
fi

# CHANGED log to debug_log
debug_log "Daemon socket is available. Waiting for service to respond..."
# NEW, CRITICAL LOOP:
for i in {1..15}; do
  if nordvpn status &> /dev/null; then
    # CHANGED log to debug_log
    debug_log "Daemon service is responsive."
    break
  fi
  sleep 1
done

if ! nordvpn status &> /dev/null; then
    log "ERROR: Daemon service failed to respond after 15 seconds."
    [ -f /var/log/nordvpn/daemon.log ] && log "Daemon Log:" && tail /var/log/nordvpn/daemon.log
    exit 1
fi
# ==========================================================
# ===== END OF ROBUST DAEMON START BLOCK ===================
# ==========================================================

# CHANGED log to debug_log
debug_log "Daemon service is responsive."

# --- ADDED BLOCK ---
# CHANGED log to debug_log
debug_log "Ensuring clean state: Forcing disconnect..."
nordvpn disconnect &> /dev/null || true # Output unterdrÃ¼ckt und Fehler abgefangen
sleep 1 # Kurze Pause geben
# --- END ADDED BLOCK ---

nordvpn set analytics disabled || true
nordvpn set technology "${VPN_TECHNOLOGY}" || true
if [ -n "${PROTOCOL}" ] && [ "${VPN_TECHNOLOGY,,}" = "openvpn" ]; then nordvpn set protocol "${PROTOCOL}" || true; fi
log "Logging in with token..."
nordvpn login --token "$TOKEN" 2>&1 | grep -v -E "Welcome|By default|To limit" || true
nordvpn set killswitch "${KILLSWITCH}" || true
nordvpn set pq "${POST_QUANTUM}" || true

# Process comma-separated allowlist
if [ -n "${ALLOWLIST_SUBNET}" ]; then
  for subnet in ${ALLOWLIST_SUBNET//,/ }; do
    log "Adding subnet to allowlist: ${subnet}"
    nordvpn allowlist add subnet "${subnet}" || true
  done
fi

nordvpn set dns 103.86.96.100 103.86.99.100 || true

# --- Connect ---
do_connect() {
  local is_reconnect="${1:-}"
  local connect_target="${VPN_SERVER}"

  if [[ "$is_reconnect" == "reconnect" ]]; then log "Reconnect detected. Using default connection method..."; connect_target=""; fi

  if [ -n "$connect_target" ]; then
    log "Connecting to server: ${connect_target}..."
    timeout "${CONNECT_TIMEOUT}" nordvpn connect "${connect_target}" &> >(handle_output) || true
  elif [ -n "${VPN_GROUP}" ]; then
    log "Connecting to group '${VPN_GROUP}' in ${VPN_COUNTRY}..."
    timeout "${CONNECT_TIMEOUT}" nordvpn connect --group "${VPN_GROUP}" "${VPN_COUNTRY}" &> >(handle_output) || true
  else
    log "Connecting to country: ${VPN_COUNTRY}..."
    timeout "${CONNECT_TIMEOUT}" nordvpn connect "${VPN_COUNTRY}" &> >(handle_output) || true
  fi

  if nordvpn status | grep -q "Status: Connected"; then
    if [[ "$is_reconnect" != "reconnect" && "${VPN_AUTO_CONNECT}" == "best" ]]; then
      VPN_SERVER=$(nordvpn status | grep 'Hostname:' | awk '{print $2}' | sed -E 's/\.nordvpn\.com//' || echo "")
    fi
  fi

  local IFACE
  for i in {1..5}; do IFACE=$(find_vpn_iface); [ -n "$IFACE" ] && break; sleep 1; done
  
  # --- ADDED PAUSE BLOCK ---
  if [ -n "$IFACE" ]; then
    log "VPN Interface $IFACE found. Waiting a few seconds for stability..."
    sleep 5 # 5 Sekunden Pause, um dem NordVPN Client Zeit zum Stabilisieren zu geben
  # --- END PAUSE BLOCK ---
    cleanup_iptables "$IFACE"
    apply_iptables "$IFACE"
    local DETECTED_MTU
    DETECTED_MTU=$(detect_mtu_for_iface "$IFACE")
    [ -n "$DETECTED_MTU" ] && apply_mtu "$IFACE" "$DETECTED_MTU"
  else
    log "WARNING: No VPN interface found after connect."
  fi

  # --- MODIFIED DNS BLOCK ---
  log "Forcing NordVPN DNS in resolv.conf for stack stability..."
  echo "nameserver 103.86.96.100" > /etc/resolv.conf
  echo "nameserver 103.86.99.100" >> /etc/resolv.conf
  # --- END MODIFIED BLOCK ---

  local VPN_IP
  VPN_IP=$(curl -s https://ipinfo.io/ip || echo "unknown")
  log "Connected. WAN IP: $VPN_IP"
}

do_connect

# ==========================================================
# ===== FINAL FUNCTION: WireGuard Server Bypass ============
# ==========================================================
if [[ "${WIREGUARD_BYPASS,,}" == "on" ]]; then
  if [ -z "$WIREGUARD_SERVER_IP" ] || [ -z "$WIREGUARD_SUBNET" ]; then
    log "ERROR: WIREGUARD_BYPASS is on, but WIREGUARD_SERVER_IP or WIREGUARD_SUBNET is not set."
  else
    log "WireGuard server bypass enabled. Applying rules for server $WIREGUARD_SERVER_IP and subnet $WIREGUARD_SUBNET..."

    # 1. Route for the return path (for data traffic)
    if ! ip route show | grep -q "${WIREGUARD_SUBNET} via ${WIREGUARD_SERVER_IP}"; then
      # CHANGED log to debug_log
      debug_log "--> Adding route for WireGuard subnet ${WIREGUARD_SUBNET}..."
      ip route add "${WIREGUARD_SUBNET}" via "${WIREGUARD_SERVER_IP}"
    else
      # CHANGED log to debug_log
      debug_log "--> Route for WireGuard subnet already exists."
    fi

    # 2. "VIP Pass" for the Killswitch (for the handshake)
    if ! iptables -t mangle -C PREROUTING -s "$WIREGUARD_SERVER_IP" -j MARK --set-xmark 0xe1f1 2>/dev/null; then
      # CHANGED log to debug_log
      debug_log "--> Adding iptables mangle rule for Killswitch bypass..."
      iptables -t mangle -I PREROUTING 1 -s "$WIREGUARD_SERVER_IP" -j MARK --set-xmark 0xe1f1
    else
      # CHANGED log to debug_log
      debug_log "--> iptables mangle rule for Killswitch bypass already exists."
    fi

    log "WireGuard bypass rules successfully applied."
  fi
fi
# ==========================================================
# ===== END OF FINAL FUNCTION ==============================
# ==========================================================


# ==========================================================
# ===== NEW FUNCTION: Log wg-easy Hooks ====================
# ==========================================================
if [[ "${SHOW_WGHOOKS,,}" == "on" ]]; then
    log "--- Recommended wg-easy PostUp/PostDown Hooks ---"
    GATEWAY_IP=$(ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
    # Extract the first subnet from the allowlist as the LAN subnet
    LAN_SUBNET=$(echo "$ALLOWLIST_SUBNET" | cut -d',' -f1)

    if [ -z "$GATEWAY_IP" ] || [ -z "$LAN_SUBNET" ] || [ -z "$WIREGUARD_SUBNET" ]; then
        log "Could not determine all required variables (Gateway IP, LAN Subnet, or WireGuard Subnet). Cannot generate hooks."
    else
        # Variant WITH local network access
        log ""
        log "--- Variant 1: WITH Local Network Access ---"
        echo ""
        log "PostUp:"
        echo "ip route add 0.0.0.0/1 via ${GATEWAY_IP}; ip route add 128.0.0.0/1 via ${GATEWAY_IP}; iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -s ${WIREGUARD_SUBNET} -d ${LAN_SUBNET} -o eth0 -j MASQUERADE"
        echo ""
        log "PostDown:"
        echo "ip route del 0.0.0.0/1; ip route del 128.0.0.0/1; iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -s ${WIREGUARD_SUBNET} -d ${LAN_SUBNET} -o eth0 -j MASQUERADE"
        echo ""

        # Variant WITHOUT local network access
        log "--- Variant 2: WITHOUT Local Network Access (Internet Only) ---"
        echo ""
        log "PostUp:"
        echo "ip route del default; ip route add default via ${GATEWAY_IP}; iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE"
        echo ""
        log "PostDown:"
        echo "iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE"
        echo ""
    fi
    log "--- End of recommended hooks ---"
fi
# ==========================================================
# ===== END OF NEW FUNCTION ================================
# ==========================================================


# --- Start background updater if enabled ---
if [[ "${VPN_AUTO_CONNECT}" == "best" && "${VPN_BEST_SERVER_CHECK_INTERVAL}" -gt 0 ]]; then
  background_best_server_updater &
  updater_pid=$! # Store PID to kill it on cleanup
fi

LAST_REFRESH=$(date +%s)
LAST_STATUS_LOG=$(date +%s)

# --- Loop ---
while true; do
  sleep "${CHECK_INTERVAL}"
  if [ "$DEBUG" = "on" ]; then ping_output=$(ping -c 1 -w 3 1.1.1.1 2>&1 || true); if [ -n "$ping_output" ]; then printf '%s\n' "$ping_output" | while IFS= read -r line; do debug_log "Keep-alive ping: $line"; done; else debug_log "Keep-alive ping: FAILED (no output)"; fi; else ping -c 1 -w 3 1.1.1.1 > /dev/null 2>&1 || true; fi
  if ! [ -S /run/nordvpn/nordvpnd.sock ]; then log "Daemon socket missing..."; service nordvpn restart || true; sleep 2; do_connect "reconnect"; LAST_REFRESH=$(date +%s); continue; fi

  # --- ADVANCED REFRESH LOGIC ---
  if [ "${VPN_REFRESH}" -gt 0 ]; then
    NOW=$(date +%s)
    ELASPED=$(( (NOW - LAST_REFRESH) / 60 ))
    if [ "$ELASPED" -ge "${VPN_REFRESH}" ]; then
      if [[ "${VPN_AUTO_CONNECT}" == "best" ]]; then
        log "Forced refresh: Finding new best server before disconnecting..."
        best_server_found=$(find_best_server || echo "")

        log "Disconnecting from current server..."
        nordvpn disconnect 2>&1 | grep -v "How would you rate" || true

        if [[ -n "$best_server_found" ]]; then
          log "New best server found: ${best_server_found}. Connecting..."
          VPN_SERVER="$best_server_found"
          do_connect
        else
          log "WARNING: Could not find a new 'best' server. Using default reconnect method."
          do_connect "reconnect"
        fi
      else
        log "Forced refresh..."
        nordvpn disconnect 2>&1 | grep -v "How would you rate" || true
        do_connect "reconnect"
      fi
      LAST_REFRESH=$NOW
      continue
    fi
  fi
  # --- END ADVANCED REFRESH LOGIC ---

  if [ "$LOG_STATUS_INTERVAL" -gt 0 ]; then NOW=$(date +%s); ELASPED=$(( (NOW - LAST_STATUS_LOG) / 60 )); if [ "$ELASPED" -ge "$LOG_STATUS_INTERVAL" ]; then STATUS=$(nordvpn status || true); UPTIME=$(echo "$STATUS" | grep -i "Uptime" | awk -F': ' '{print $2}'); TRANSFER=$(echo "$STATUS" | grep -i "Transfer" | awk -F': ' '{print $2}'); log "Session status - Uptime: ${UPTIME:-unknown}, Transfer: ${TRANSFER:-unknown}"; LAST_STATUS_LOG=$NOW; fi; fi

  STATUS=$(nordvpn status || true)
  if ! echo "$STATUS" | grep -q "Status: Connected"; then
    log "VPN not connected -> reconnecting..."

    reconnect_server=""
    if [[ "${VPN_AUTO_CONNECT}" == "best" && -s $BEST_SERVER_CACHE_FILE ]]; then
      reconnect_server=$(cat "$BEST_SERVER_CACHE_FILE")
      log "Using pre-cached best server for reconnect: ${reconnect_server}"
      VPN_SERVER="$reconnect_server"
      nordvpn disconnect 2>&1 | grep -v "How would you rate" || true
      do_connect
    else
      # Fallback to the old method
      nordvpn disconnect 2>&1 | grep -v "How would you rate" || true
      do_connect "reconnect"
    fi
    continue
  fi

  SUCCESS=0; attempt=0
  while [ "$attempt" -lt "$RETRY_COUNT" ]; do attempt=$((attempt+1)); if curl -s --max-time 10 https://www.google.com > /dev/null; then SUCCESS=1; break; fi; [ "$attempt" -lt "$RETRY_COUNT" ] && sleep "$RETRY_DELAY"; done
  if [ "$SUCCESS" -eq 0 ]; then log "Connectivity check FAILED -> reconnecting..."; nordvpn disconnect 2>&1 | grep -v "How would you rate" || true; do_connect "reconnect"; continue; fi
done
