#!/bin/bash
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $1"; }
info() { echo -e "${CYAN}[i]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error(){ echo -e "${RED}[!]${NC} $1"; exit 1; }

[[ $EUID -ne 0 ]] && error "Run as root: sudo bash install.sh"

APP_DIR=/opt/webseccheck
APP_USER=webseccheck
VENV_DIR="$APP_DIR/venv"
LOG_DIR=/var/log/webseccheck
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${CYAN}"
echo "  ╔══════════════════════════════════════╗"
echo "  ║   WebSecCheck — Installation Script  ║"
echo "  ║   OWASP Top 10 Security Testing      ║"
echo "  ╚══════════════════════════════════════╝"
echo -e "${NC}"

log "Updating system packages..."
apt-get update -qq
apt-get install -y \
    python3.12 python3.12-venv python3.12-dev python3-pip \
    redis-server nginx git curl build-essential \
    libssl-dev libffi-dev pkg-config \
    2>/dev/null

log "Creating application user '$APP_USER'..."
if ! id -u "$APP_USER" &>/dev/null; then
    useradd -r -s /bin/false -d "$APP_DIR" "$APP_USER"
fi

log "Creating directories..."
mkdir -p "$APP_DIR" "$LOG_DIR"

log "Copying application files to $APP_DIR..."
rsync -a --exclude='.git' --exclude='venv' --exclude='__pycache__' \
    "$SCRIPT_DIR/" "$APP_DIR/"
chown -R "$APP_USER:$APP_USER" "$APP_DIR" "$LOG_DIR"
chmod 750 "$APP_DIR"

log "Creating Python virtual environment..."
python3.12 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip --quiet
"$VENV_DIR/bin/pip" install -r "$APP_DIR/requirements.txt" --quiet

log "Configuring environment..."
if [ ! -f "$APP_DIR/.env" ]; then
    cp "$APP_DIR/.env.example" "$APP_DIR/.env"
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    sed -i "s|SECRET_KEY=.*|SECRET_KEY=$SECRET_KEY|" "$APP_DIR/.env"
    warn "Edit $APP_DIR/.env to set MAIL_SERVER and other settings."
fi
chown "$APP_USER:$APP_USER" "$APP_DIR/.env"
chmod 600 "$APP_DIR/.env"

log "Initializing database..."
cd "$APP_DIR"
sudo -u "$APP_USER" "$VENV_DIR/bin/python" init_db.py

log "Creating first admin user..."
sudo -u "$APP_USER" "$VENV_DIR/bin/python" create_admin.py

log "Installing systemd services..."
cp "$APP_DIR/systemd/webseccheck.service" /etc/systemd/system/
cp "$APP_DIR/systemd/webseccheck-celery.service" /etc/systemd/system/
sed -i "s|/opt/webseccheck|$APP_DIR|g" /etc/systemd/system/webseccheck.service
sed -i "s|/opt/webseccheck|$APP_DIR|g" /etc/systemd/system/webseccheck-celery.service
systemctl daemon-reload
systemctl enable webseccheck webseccheck-celery

log "Enabling Redis..."
systemctl enable --now redis-server

log "Configuring nginx..."
mkdir -p /etc/ssl/webseccheck
cp "$APP_DIR/nginx/webseccheck.conf" /etc/nginx/sites-available/webseccheck
ln -sf /etc/nginx/sites-available/webseccheck /etc/nginx/sites-enabled/webseccheck
rm -f /etc/nginx/sites-enabled/default

# Update static path in nginx config
sed -i "s|/opt/webseccheck|$APP_DIR|g" /etc/nginx/sites-available/webseccheck

nginx -t 2>/dev/null && log "Nginx configuration valid." || warn "Nginx config has errors — check /etc/nginx/sites-available/webseccheck"
systemctl restart nginx || warn "Nginx restart failed — may need SSL cert first."

echo ""
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN} Installation complete!${NC}"
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo ""
echo -e "${CYAN}Required next steps:${NC}"
echo ""
echo "1. Edit environment config:"
echo "   nano $APP_DIR/.env"
echo "   (Set MAIL_SERVER, APP_DOMAIN, and other settings)"
echo ""
echo "2. Generate a self-signed SSL certificate:"
echo "   mkdir -p /etc/ssl/webseccheck"
echo "   openssl req -x509 -nodes -days 365 -newkey rsa:4096 \\"
echo "     -keyout /etc/ssl/webseccheck/key.pem \\"
echo "     -out /etc/ssl/webseccheck/cert.pem \\"
echo "     -subj '/CN=YOUR_DOMAIN_OR_IP'"
echo "   chown root:$APP_USER /etc/ssl/webseccheck/key.pem"
echo "   chmod 640 /etc/ssl/webseccheck/key.pem"
echo ""
echo "3. Update nginx config with your domain/IP:"
echo "   nano /etc/nginx/sites-available/webseccheck"
echo "   (Replace YOUR_DOMAIN with your actual domain or IP)"
echo "   nginx -t && systemctl reload nginx"
echo ""
echo "4. Start the application services:"
echo "   systemctl start webseccheck webseccheck-celery"
echo "   systemctl status webseccheck"
echo ""
echo "5. Access WebSecCheck at:"
echo "   https://YOUR_DOMAIN"
echo ""
echo -e "${YELLOW}Logs:${NC} $LOG_DIR/"
echo -e "${YELLOW}Config:${NC} $APP_DIR/.env"
echo -e "${YELLOW}Nginx:${NC} /etc/nginx/sites-available/webseccheck"
