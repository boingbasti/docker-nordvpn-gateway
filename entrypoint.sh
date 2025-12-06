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
  
  # --- FLUSH CONNTRACK ---
  # Clear the connection tracking table to remove stale entries
  # that might cause issues (e.g., with wg-easy) after a reconnect.
  log "INFO: Flushing connection tracking table (conntrack)..."
  if command -v conntrack >/dev/null; then
      conntrack -F
  else
      log "WARN: conntrack command not found. Skipping flush."
  fi
  # --- END FLUSH CONNTRACK ---

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

  # --- ROBUST DAEMON STOP ---
  log "Stopping NordVPN service daemon (nordvpnd)..."
  
  # 1. Try a graceful service stop
  service nordvpn stop &> /dev/null || true
  sleep 2

  # 2. Check if the process is still running
  if pgrep -x "nordvpnd" > /dev/null; then
    log "Daemon is still running. Sending SIGTERM..."
    # 3. Send SIGTERM (graceful kill)
    pkill -TERM nordvpnd || true
    sleep 3
  fi

  # 4. Final check
  if pgrep -x "nordvpnd" > /dev/null; then
    log "Daemon did not respond to SIGTERM. Sending SIGKILL (force)..."
    # 5. Send SIGKILL (forceful kill)
    pkill -9 nordvpnd || true
    sleep 1
  fi
  
  log "NordVPN daemon stopped."
  # --- END ROBUST DAEMON STOP ---

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
# Defaults for WireGuard Support
WIREGUARD_BYPASS=${WIREGUARD_BYPASS:-off}
WIREGUARD_SERVER_IP=${WIREGUARD_SERVER_IP:-}
WIREGUARD_SUBNET=${WIREGUARD_SUBNET:-}
# Defaults for logging hooks
SHOW_WGHOOKS=${SHOW_WGHOOKS:-off}
# Speed Test Defaults
VPN_SPEED_CHECK_INTERVAL=${VPN_SPEED_CHECK_INTERVAL:-0} # In Minuten, 0 = deaktiviert
VPN_MIN_SPEED=${VPN_MIN_SPEED:-5} # In MBit/s
SPEED_TEST_URL=${SPEED_TEST_URL:-"http://cachefly.cachefly.net/10mb.test"}
THREAT_PROTECTION_LITE=${THREAT_PROTECTION_LITE:-off}

# --- FIX: Handle 'standard' group ---
# NordVPN uses no group flag for standard servers, so we clear the variable.
if [[ "${VPN_GROUP,,}" == "standard" ]]; then
  log "Configured group is 'standard'. Connecting without specific group flag."
  VPN_GROUP=""
fi

# MTU cache
MTU_CACHE=""
BEST_SERVER_CACHE_FILE="/tmp/best_server.txt"
SERVER_CANDIDATES_FILE="/tmp/server_candidates"

# --- Function: Determine MTU via Ping Test ---
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

# --- IPTables Helpers ---
apply_iptables() {
  local IFACE="$1"
  if [ -z "$IFACE" ]; then return; fi
  log "Applying iptables rules (iface=$IFACE)..."
  # Iterate through comma-separated subnets
  for subnet in ${ALLOWLIST_SUBNET//,/ }; do
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
# --- End IPTables Helpers ---

# --- Function: WireGuard Server Bypass ---
apply_wg_bypass_rules() {
  if [[ "${WIREGUARD_BYPASS,,}" == "on" ]]; then
    if [ -z "$WIREGUARD_SERVER_IP" ] || [ -z "$WIREGUARD_SUBNET" ]; then
      log "ERROR: WIREGUARD_BYPASS is on, but WIREGUARD_SERVER_IP or WIREGUARD_SUBNET is not set."
    else
      log "WireGuard server bypass enabled. Re-applying rules for server $WIREGUARD_SERVER_IP and subnet $WIREGUARD_SUBNET..."

      # 1. Route for the return path (for data traffic)
      if ! ip route show | grep -q "${WIREGUARD_SUBNET} via ${WIREGUARD_SERVER_IP}"; then
        debug_log "--> Adding route for WireGuard subnet ${WIREGUARD_SUBNET}..."
        ip route add "${WIREGUARD_SUBNET}" via "${WIREGUARD_SERVER_IP}"
      else
        debug_log "--> Route for WireGuard subnet already exists."
      fi

      # 2. "VIP Pass" for the Killswitch (for the handshake)
      debug_log "--> (Re)applying iptables mangle rule for Killswitch bypass..."
      iptables -t mangle -D PREROUTING -s "$WIREGUARD_SERVER_IP" -j MARK --set-xmark 0xe1f1 2>/dev/null || true
      iptables -t mangle -I PREROUTING 1 -s "$WIREGUARD_SERVER_IP" -j MARK --set-xmark 0xe1f1
      
      log "WireGuard bypass rules successfully applied."
    fi
  fi
}
# --- ENDE FUNKTION ---

apply_mtu() { IFACE="$1"; MTU_VAL="$2"; if [ -n "$IFACE" ] && [[ "$MTU_VAL" =~ ^[0-9]+$ ]]; then log "Setting MTU $MTU_VAL on $IFACE..."; ip link set dev "$IFACE" mtu "$MTU_VAL" || true; fi; }

# --- Function: Determine MTU ---
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

  # Handle empty group identifier (standard servers) properly in query
  local group_filter=""
  if [ -n "$api_group_identifier" ]; then
      debug_log "Fetching group ID for '${VPN_GROUP}' (using API identifier '${api_group_identifier}')..."
      local group_id
      group_id=$(curl -s 'https://api.nordvpn.com/v1/servers/groups' | jq --arg GROUP "$api_group_identifier" '.[] | select(.identifier == $GROUP) | .id')
      if [[ -z "$group_id" ]]; then log "Error: Could not find group ID for '${VPN_GROUP}'."; return 1; fi
      debug_log "Found group ID: ${group_id}"
      group_filter="&filters[servers_groups][id]=${group_id}"
  fi

  debug_log "--> Step 1: Fetching recommended servers from NordVPN API..."
  local server_list
  server_list=$(curl -s -g "https://api.nordvpn.com/v1/servers/recommendations?filters[country_id]=${country_id}${group_filter}&limit=15" | \
    jq -r '.[].hostname')

  if [[ -z "$server_list" ]]; then log "Error: No recommended servers found."; return 1; fi

  debug_log "--> Step 2: Quality Ping (3 packets, strict 0% loss check) to find best latency..."
  local ping_results
  ping_results=$(
    for server in $server_list; do
      (
        # Send 3 Pings, fast interval (0.2s), 1s timeout, quiet output
        local ping_output
        ping_output=$(ping -c 3 -q -i 0.2 -W 1 "$server" 2>&1)
        
        # Only accept servers with 0% packet loss
        if echo "$ping_output" | grep -q "0% packet loss"; then
          # Extract Average RTT (avg) from line like: "rtt min/avg/max/mdev = 13.9/14.0/14.1/0.1 ms"
          local latency
          latency=$(echo "$ping_output" | grep "rtt" | cut -d'=' -f2 | awk -F'/' '{print $2}')
          
          if [ -n "$latency" ]; then
            printf "%.2f %s\n" "$latency" "$server"
          fi
        fi
      ) &
    done
    wait
  )

  if [ -z "$ping_results" ]; then log "Error: Quality Ping (strict 0% loss) could not find any responsive servers."; return 1; fi

  # Sort by latency
  local sorted_results
  sorted_results=$(echo "$ping_results" | sort -n)

  # --- NEW: Candidate Logic ---
  # Save top 3 servers to candidate file (server IDs only)
  echo "$sorted_results" | head -n 3 | awk '{print $2}' | sed -E 's/\.nordvpn\.com//' > "$SERVER_CANDIDATES_FILE"
  
  # Return the best one
  echo "$sorted_results" | head -n 1 | awk '{print $2}' | sed -E 's/\.nordvpn\.com//'
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

# --- Shared Speed Test & Candidate Rotation Logic ---
perform_speed_check() {
  # If speed check is disabled (interval=0) and we are not forcing it (e.g. startup), skip.
  # But we want to use min_speed as a threshold anyway.
  if [ "${VPN_MIN_SPEED}" -le 0 ]; then return; fi

  debug_log "Running speed check (Threshold: ${VPN_MIN_SPEED} MBit/s)..."
  
  # Convert MBit/s to Bytes/s
  local MIN_SPEED_BYTES=$(( VPN_MIN_SPEED * 125000 ))
  
  # Run test
  local CURRENT_SPEED
  CURRENT_SPEED=$(curl -w '%{speed_download}\n' -o /dev/null -s --max-time 20 "$SPEED_TEST_URL" | cut -d'.' -f1 || echo 0)
  
  debug_log "Speed test result: ${CURRENT_SPEED} Bytes/s."

  if [ "$CURRENT_SPEED" -lt "$MIN_SPEED_BYTES" ] && [ "$CURRENT_SPEED" -ne 0 ]; then
    log "WARNING: Speed check FAILED. Speed (${CURRENT_SPEED} B/s) < Threshold (${MIN_SPEED_BYTES} B/s)."
    
    # 1. Check for candidates (Thronfolger)
    if [ -s "$SERVER_CANDIDATES_FILE" ]; then
        # Identify current server ID from status
        local current_server_id
        current_server_id=$(nordvpn status | grep 'Hostname:' | awk '{print $2}' | sed -E 's/\.nordvpn\.com//')
        
        # Remove current server from candidates list (burn it)
        if [ -n "$current_server_id" ]; then
            sed -i "/$current_server_id/d" "$SERVER_CANDIDATES_FILE"
        fi
        
        # Pick next candidate
        local next_candidate
        next_candidate=$(head -n 1 "$SERVER_CANDIDATES_FILE")
        
        if [ -n "$next_candidate" ]; then
            log "Candidate available! Switching to next best server: ${next_candidate}..."
            VPN_SERVER="$next_candidate"
            
            # Flush conntrack
            if command -v conntrack >/dev/null; then conntrack -F; fi
            
            nordvpn disconnect 2>&1 | grep -v "How would you rate" || true
            do_connect # Reconnect using VPN_SERVER variable
            
            # --- NEW: Verify the new candidate recursively ---
            log "Verifying speed of new candidate in 15 seconds..."
            sleep 15
            perform_speed_check
            return # Exit this instance of the function
        else
             log "No valid candidates left in list."
        fi
    fi

    # 2. Fallback: Standard Reconnect (if no candidates or candidates empty)
    # We do NOT run a recursive check here to prevent infinite loops if the whole network is slow.
    log "Triggering standard reconnect (letting NordVPN decide)..."
    if command -v conntrack >/dev/null; then conntrack -F; fi
    
    # Clear cache and specific server var to allow fresh search or standard connect
    rm -f "$BEST_SERVER_CACHE_FILE"
    VPN_SERVER="" 
    
    nordvpn disconnect 2>&1 | grep -v "How would you rate" || true
    do_connect "reconnect"
    
  else
    debug_log "Speed check PASSED."
  fi
}

# --- NEW: Check Connectivity Quality (The Watchdog) ---
check_connection_quality() {
    # Check internet connectivity AND quality (Packet Loss / Latency)
    # Using 1.1.1.1 (Cloudflare) as a stable target
    local target="1.1.1.1"
    
    # Send 3 pings, fast interval (0.2s), 2s timeout
    local ping_out
    ping_out=$(ping -c 3 -q -i 0.2 -W 2 "$target" 2>&1 || true)
    
    # Extract avg RTT
    local avg_rtt
    avg_rtt=$(echo "$ping_out" | grep "rtt" | cut -d'=' -f2 | awk -F'/' '{print $2}' | cut -d'.' -f1)

    # 1. Check for ANY Packet Loss (Strict Watchdog)
    # If 100% loss -> Dead. If > 0% loss -> Unstable.
    if ! echo "$ping_out" | grep -q "0% packet loss"; then
        debug_log "Watchdog: Packet loss detected! Connection unstable or dead."
        return 1
    fi
    
    # 2. Check Latency (Lag Watchdog)
    # Threshold: 600ms (High latency but generous enough to avoid false positives)
    if [ -n "$avg_rtt" ] && [ "$avg_rtt" -gt 600 ]; then
        debug_log "Watchdog: Latency too high (${avg_rtt}ms)."
        return 1
    fi
    
    # Success Log (Visible in DEBUG=on)
    if [ -n "$avg_rtt" ]; then
        debug_log "Watchdog: Connection healthy (Avg RTT: ${avg_rtt}ms, Packet Loss: 0%)."
    fi
    
    return 0
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
    # Prime the cache file
    echo "$best_server_found" > "$BEST_SERVER_CACHE_FILE"
  else
    log "WARNING: Could not find a 'best' server. Using default connection method."
  fi
fi

# --- Robust Daemon Start ---
log "Ensuring no stray daemon is running..."
pkill -9 nordvpnd || true
rm -f /run/nordvpn/nordvpnd.sock
sleep 1

log "Starting NordVPN service daemon..."
service nordvpn start || true
sleep 2

debug_log "Waiting for daemon socket file..."
for i in {1..15}; do [ -S /run/nordvpn/nordvpnd.sock ] && break; sleep 1; done

if ! [ -S /run/nordvpn/nordvpnd.sock ]; then
  log "ERROR: Daemon socket file (/run/nordvpn/nordvpnd.sock) did not appear after 15 seconds."
  [ -f /var/log/nordvpn/daemon.log ] && log "Daemon Log:" && tail /var/log/nordvpn/daemon.log
  exit 1
fi

debug_log "Daemon socket is available. Waiting for service to respond..."
for i in {1..15}; do
  if nordvpn status &> /dev/null; then
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
# --- End Robust Daemon Start ---

debug_log "Daemon service is responsive."

debug_log "Ensuring clean state: Forcing disconnect..."
nordvpn disconnect &> /dev/null || true
sleep 1 

# --- Configuration Settings ---
nordvpn set analytics disabled || true
nordvpn set technology "${VPN_TECHNOLOGY}" || true
if [ -n "${PROTOCOL}" ] && [ "${VPN_TECHNOLOGY,,}" = "openvpn" ]; then nordvpn set protocol "${PROTOCOL}" || true; fi
log "Logging in with token..."
nordvpn login --token "$TOKEN" 2>&1 | grep -v -E "Welcome|By default|To limit" || true
nordvpn set killswitch "${KILLSWITCH}" || true
nordvpn set pq "${POST_QUANTUM}" || true

# --- Feature Settings ---
nordvpn set notify off || true
nordvpn set threatprotectionlite "$THREAT_PROTECTION_LITE" || true

# Process comma-separated allowlist
if [ -n "${ALLOWLIST_SUBNET}" ]; then
  for subnet in ${ALLOWLIST_SUBNET//,/ }; do
    log "Adding subnet to allowlist: ${subnet}"
    nordvpn allowlist add subnet "${subnet}" || true
  done
fi

# --- DNS Handling ---
if [ "$THREAT_PROTECTION_LITE" != "on" ]; then
    log "Setting standard NordVPN DNS (103.86.x.x) to prevent DNS leaks."
    nordvpn set dns 103.86.96.100 103.86.99.100 || true
else
    log "Threat Protection Lite is active. Skipping manual DNS setting."
fi

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
    # If VPN_GROUP is empty (standard), this command connects correctly to the country
    timeout "${CONNECT_TIMEOUT}" nordvpn connect "${VPN_COUNTRY}" &> >(handle_output) || true
  fi

  if nordvpn status | grep -q "Status: Connected"; then
    if [[ "$is_reconnect" != "reconnect" && "${VPN_AUTO_CONNECT}" == "best" ]]; then
      VPN_SERVER=$(nordvpn status | grep 'Hostname:' | awk '{print $2}' | sed -E 's/\.nordvpn\.com//' || echo "")
    fi
  fi

  local IFACE
  for i in {1..5}; do IFACE=$(find_vpn_iface); [ -n "$IFACE" ] && break; sleep 1; done
  
  # Pause for interface stability
  if [ -n "$IFACE" ]; then
    log "VPN Interface $IFACE found. Waiting a few seconds for stability..."
    sleep 5 # Give the client time to stabilize
    cleanup_iptables "$IFACE"
    apply_iptables "$IFACE"
    local DETECTED_MTU
    DETECTED_MTU=$(detect_mtu_for_iface "$IFACE")
    [ -n "$DETECTED_MTU" ] && apply_mtu "$IFACE" "$DETECTED_MTU"

    # WG-Bypass rules apply here (Inside the function for reconnects)
    apply_wg_bypass_rules

  else
    log "WARNING: No VPN interface found after connect."
  fi

  # --- DNS Forcing ---
  if [ "$THREAT_PROTECTION_LITE" != "on" ]; then
    log "Forcing NordVPN DNS in resolv.conf for stack stability..."
    echo "nameserver 103.86.96.100" > /etc/resolv.conf
    echo "nameserver 103.86.99.100" >> /etc/resolv.conf
  else
    log "Threat Protection Lite is active. Trusting client DNS settings in resolv.conf."
  fi

  local VPN_IP
  VPN_IP=$(curl -s https://ipinfo.io/ip || echo "unknown")
  log "Connected. WAN IP: $VPN_IP"
}

do_connect

# --- Log wg-easy Hooks ---
if [[ "${SHOW_WGHOOKS,,}" == "on" ]]; then
    log "--- Recommended wg-easy PostUp/PostDown Hooks ---"
    GATEWAY_IP=$(ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
    LAN_SUBNET=$(echo "$ALLOWLIST_SUBNET" | cut -d',' -f1)

    if [ -z "$GATEWAY_IP" ] || [ -z "$LAN_SUBNET" ] || [ -z "$WIREGUARD_SUBNET" ]; then
        log "Could not determine all required variables. Cannot generate hooks."
    else
        log ""
        log "--- Variant 1: WITH Local Network Access ---"
        echo ""
        log "PostUp:"
        echo "ip route add 0.0.0.0/1 via ${GATEWAY_IP}; ip route add 128.0.0.0/1 via ${GATEWAY_IP}; iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -s ${WIREGUARD_SUBNET} -d ${LAN_SUBNET} -o eth0 -j MASQUERADE"
        echo ""
        log "PostDown:"
        echo "ip route del 0.0.0.0/1; ip route del 128.0.0.0/1; iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -s ${WIREGUARD_SUBNET} -d ${LAN_SUBNET} -o eth0 -j MASQUERADE"
        echo ""
        
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

# --- STARTUP: Immediate Speed Check ---
# Wait 10s for connection to fully stabilize, then check speed.
if [ "${VPN_SPEED_CHECK_INTERVAL}" -gt 0 ]; then
    log "Initializing immediate startup speed check (in 15s)..."
    sleep 15
    perform_speed_check
    
    # --- NEW: Final Success Message ---
    # We fetch the IP again to confirm everything is routed correctly after the test
    CURRENT_IP=$(curl -s --max-time 5 https://ipinfo.io/ip || echo "unknown")
    log "✅ Startup complete. VPN connection stable. Current WAN IP: ${CURRENT_IP}"
else
    # If speed check is disabled, just print the success message immediately
    CURRENT_IP=$(curl -s --max-time 5 https://ipinfo.io/ip || echo "unknown")
    log "✅ Startup complete. VPN connection stable. Current WAN IP: ${CURRENT_IP}"
fi

# --- Start background updater if enabled ---
if [[ "${VPN_AUTO_CONNECT}" == "best" && "${VPN_BEST_SERVER_CHECK_INTERVAL}" -gt 0 ]]; then
  background_best_server_updater &
  updater_pid=$! # Store PID to kill it on cleanup
fi

LAST_REFRESH=$(date +%s)
LAST_STATUS_LOG=$(date +%s)
LAST_SPEED_TEST=$(date +%s)

# --- Loop ---
while true; do
  sleep "${CHECK_INTERVAL}"
  
  # --- DEBUG LOGGING ---
  if [ "$DEBUG" = "on" ]; then ping_output=$(ping -c 1 -w 3 1.1.1.1 2>&1 || true); if [ -n "$ping_output" ]; then printf '%s\n' "$ping_output" | while IFS= read -r line; do debug_log "Keep-alive ping: $line"; done; else debug_log "Keep-alive ping: FAILED (no output)"; fi; else ping -c 1 -w 3 1.1.1.1 > /dev/null 2>&1 || true; fi
  
  if ! [ -S /run/nordvpn/nordvpnd.sock ]; then log "Daemon socket missing..."; service nordvpn restart || true; sleep 2; do_connect "reconnect"; LAST_REFRESH=$(date +%s); continue; fi

  NOW=$(date +%s)

  # --- ADVANCED REFRESH LOGIC ---
  if [ "${VPN_REFRESH}" -gt 0 ]; then
    ELASPED=$(( (NOW - LAST_REFRESH) / 60 ))
    if [ "$ELASPED" -ge "${VPN_REFRESH}" ]; then
      
      log "INFO: Flushing conntrack before forced refresh..."
      if command -v conntrack >/dev/null; then conntrack -F; fi

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

  # --- LOG STATUS LOGIC ---
  if [ "$LOG_STATUS_INTERVAL" -gt 0 ]; then ELASPED=$(( (NOW - LAST_STATUS_LOG) / 60 )); if [ "$ELASPED" -ge "$LOG_STATUS_INTERVAL" ]; then STATUS=$(nordvpn status || true); UPTIME=$(echo "$STATUS" | grep -i "Uptime" | awk -F': ' '{print $2}'); TRANSFER=$(echo "$STATUS" | grep -i "Transfer" | awk -F': ' '{print $2}'); log "Session status - Uptime: ${UPTIME:-unknown}, Transfer: ${TRANSFER:-unknown}"; LAST_STATUS_LOG=$NOW; fi; fi

  # --- SPEED-TEST BLOCK ---
  if [ "${VPN_SPEED_CHECK_INTERVAL}" -gt 0 ]; then
    ELASPED_SPEED=$(( (NOW - LAST_SPEED_TEST) / 60 ))
    if [ "$ELASPED_SPEED" -ge "${VPN_SPEED_CHECK_INTERVAL}" ]; then
      perform_speed_check
      LAST_SPEED_TEST=$NOW
    fi
  fi
  # --- END SPEED-TEST BLOCK ---

  # --- STANDARD RECONNECT LOGIC & WATCHDOG ---
  
  STATUS=$(nordvpn status || true)
  
  # 1. Check if connected status is reported
  if ! echo "$STATUS" | grep -q "Status: Connected"; then
    log "VPN not connected -> reconnecting..."
    # Reconnect logic (flush conntrack, reset server if needed)
    if command -v conntrack >/dev/null; then conntrack -F; fi
    nordvpn disconnect 2>&1 | grep -v "How would you rate" || true
    do_connect "reconnect"
    continue
  fi

  # 2. WATCHDOG: Check Connection Quality (Packet Loss / Latency)
  # This replaces the old curl check. It detects "zombie" connections.
  SUCCESS=0
  attempt=0
  while [ "$attempt" -lt "$RETRY_COUNT" ]; do
      attempt=$((attempt+1))
      
      if check_connection_quality; then
          SUCCESS=1
          
          # NEW: Silent Healing Feedback (only visible in debug)
          if [ "$attempt" -gt 1 ]; then
              debug_log "✅ Watchdog: Connection recovered on attempt $attempt. False alarm."
          fi
          break
      fi
      
      # Warning only in debug, to keep main log clean unless it fails completely
      if [ "$attempt" -lt "$RETRY_COUNT" ]; then
          debug_log "⚠️ Watchdog: Connection issue detected (Attempt $attempt/$RETRY_COUNT). Retrying in $RETRY_DELAY seconds..."
          sleep "$RETRY_DELAY"
      fi
  done

  if [ "$SUCCESS" -eq 0 ]; then
      log "❌ Watchdog FAILED (High Packet Loss or Latency) -> Triggering Reconnect..."
      nordvpn disconnect 2>&1 | grep -v "How would you rate" || true
      
      # Important: If this happens, the current server is bad. 
      # Ideally, we should treat this like a speed test fail.
      # For now, a standard reconnect usually picks a new server.
      do_connect "reconnect"
      continue
  fi
  
done