#!/usr/bin/env bash
# =============================================================================
# Automated EC2 Bootstrap & Deploy Script for AI Attack Surface & Strands Decider
# Supports: Amazon Linux 2023, Ubuntu 22.04 / 24.04 LTS
# =============================================================================
set -euo pipefail

echo "======================================================================"
echo " [*] Starting EC2 Host Deployment for Strands Decider & Security Agent"
echo "======================================================================"

# 1. Detect OS Distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "[-] Cannot determine OS. /etc/os-release missing."
    exit 1
fi

echo "[+] Detected OS: $OS"

# 2. Install Docker and Docker Compose Plugin
if [ "$OS" = "amzn" ]; then
    echo "[+] Installing Docker on Amazon Linux 2023..."
    sudo dnf update -y
    sudo dnf install -y docker git
    sudo systemctl enable --now docker
    sudo usermod -aG docker "$USER" || true

    # Install Docker Compose Plugin v2
    DOCKER_CONFIG=${DOCKER_CONFIG:-/usr/local/lib/docker}
    sudo mkdir -p $DOCKER_CONFIG/cli-plugins
    sudo curl -SL "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-$(uname -m)" -o $DOCKER_CONFIG/cli-plugins/docker-compose
    sudo chmod +x $DOCKER_CONFIG/cli-plugins/docker-compose

elif [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
    echo "[+] Installing Docker on Ubuntu/Debian..."
    sudo apt-get update -y
    sudo apt-get install -y ca-certificates curl gnupg git
    sudo install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg --yes
    sudo chmod a+r /etc/apt/keyrings/docker.gpg

    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    sudo apt-get update -y
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    sudo systemctl enable --now docker
    sudo usermod -aG docker "$USER" || true
else
    echo "[-] Unsupported distribution: $OS"
    exit 1
fi

echo "[+] Docker installation verified: $(docker --version)"
echo "[+] Docker Compose verified: $(docker compose version)"

# 3. Setup Project Directory
APP_DIR="/opt/ai-attack-surface-tool"
if [ ! -d "$APP_DIR" ]; then
    echo "[+] Setting up project directory at $APP_DIR..."
    sudo mkdir -p "$APP_DIR"
    sudo chown -R "$USER:$USER" "$APP_DIR"
    # If script is run inside the repo, copy files; otherwise clone
    if [ -f "docker-compose.yml" ]; then
        cp -r . "$APP_DIR/"
    fi
fi

cd "$APP_DIR"

# 4. Configure Environment (.env)
if [ ! -f .env ]; then
    echo "[*] Creating .env from .env.example..."
    cp .env.example .env
    # Generate a strong dashboard password if default placeholder is present
    RANDOM_PASS=$(head -c 16 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 16)
    sed -i "s/replace_with_a_long_random_password/$RANDOM_PASS/g" .env
    echo "======================================================================"
    echo " [!] GENERATED DASHBOARD PASSWORD: $RANDOM_PASS"
    echo "     (Save this password to log in to the dashboard)"
    echo "======================================================================"
fi

# Ensure data directory exists
mkdir -p data data/history

# 5. Build and Launch Containers via Docker Compose
echo "[+] Building and starting Docker Compose services..."
docker compose build --pull
docker compose up -d

echo "[+] Waiting for services to become healthy..."
docker compose ps

echo "======================================================================"
echo " [+] Deployment Complete!"
echo "     Dashboard URL: http://$(curl -s http://checkip.amazonaws.com || echo 'YOUR_EC2_IP'):8501"
echo "     Health status: docker compose ps"
echo "     Logs:          docker compose logs -f"
echo "======================================================================"
