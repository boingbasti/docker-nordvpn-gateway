FROM ubuntu:24.04

LABEL maintainer="boingbasti" \
      description="NordVPN Gateway Container" \
      version="2.0-stable"

# Install dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      curl \
      wget \
      iptables \
      iproute2 \
      gnupg \
      lsb-release \
      wireguard-tools \
      iputils-ping \
      jq \
      conntrack \
      ca-certificates && \
    # Add NordVPN repo key and list
    wget -qO /etc/apt/trusted.gpg.d/nordvpn_public.asc https://repo.nordvpn.com/gpg/nordvpn_public.asc && \
    echo "deb https://repo.nordvpn.com/deb/nordvpn/debian stable main" > /etc/apt/sources.list.d/nordvpn.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends nordvpn && \
    # Cleanup
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Add Docker healthcheck
HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
  CMD curl -fsSL --max-time 5 https://1.1.1.1 || exit 1

# Start
ENTRYPOINT ["/entrypoint.sh"]
