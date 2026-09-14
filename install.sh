#!/bin/bash
set -euo pipefail

# ==============================================================================
# Clamguard Daemon Installation Script
# ==============================================================================

BOLD="\033[1m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
CYAN="\033[0;36m"
NC="\033[0m"

log_info() {
    echo -e "${CYAN}[INFO]${NC} $*"
}

log_pass() {
    echo -e "${GREEN}[OK]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_NAME="clamguard"
SERVICE_NAME="clamguard.service"
INSTALL_BIN_PATH="/usr/local/bin/${BIN_NAME}"
INSTALL_SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}"

# 1. Require root / sudo
if [ "$EUID" -ne 0 ]; then
    log_error "This script must be run as root. Please run with sudo: sudo ./install.sh"
    exit 1
fi

echo -e "${BOLD}Installing Clamguard Daemon...${NC}\n"

# 2. Install binary
log_info "Installing binary to ${INSTALL_BIN_PATH}..."
install -m 755 "${SCRIPT_DIR}/${BIN_NAME}" "${INSTALL_BIN_PATH}"
log_pass "Installed binary."

# 3. Install systemd unit
if [ -f "${SCRIPT_DIR}/${SERVICE_NAME}" ]; then
    log_info "Installing systemd unit to ${INSTALL_SERVICE_PATH}..."
    install -m 644 "${SCRIPT_DIR}/${SERVICE_NAME}" "${INSTALL_SERVICE_PATH}"
    sed -i "s|<BIN_PATH>|${INSTALL_BIN_PATH}|" "${INSTALL_SERVICE_PATH}"
    log_pass "Installed systemd unit."
else
    log_error "Service file '${SERVICE_NAME}' not found in repository root."
    exit 1
fi

# 4. Reload systemd daemon
log_info "Reloading systemd daemon..."
systemctl daemon-reload
log_pass "Systemd reloaded."

# 5. Check ClamAV status
echo ""
log_info "Checking ClamAV service status..."
CLAMD_FOUND=0
for svc in clamav-daemon clamav-daemon.socket clamd@scan clamd; do
    if systemctl is-active --quiet "${svc}" 2>/dev/null; then
        log_pass "${svc} is active."
        CLAMD_FOUND=1
        break
    fi
done

if [ "${CLAMD_FOUND}" -eq 0 ]; then
    log_warn "ClamAV daemon service is currently inactive. Ensure ClamAV is started:"
    echo "       Ubuntu/Debian:  sudo systemctl enable --now clamav-daemon"
    echo "       Fedora/RHEL:    sudo systemctl enable --now clamd@scan"
    echo "       Arch/openSUSE:  sudo systemctl enable --now clamd"
fi

FRESHCLAM_FOUND=0
for svc in clamav-freshclam freshclam; do
    if systemctl is-active --quiet "${svc}" 2>/dev/null; then
        log_pass "${svc} (signature updater) is active."
        FRESHCLAM_FOUND=1
        break
    fi
done

if [ "${FRESHCLAM_FOUND}" -eq 0 ]; then
    log_warn "ClamAV signature updater is inactive. Ensure signature updates are enabled:"
    echo "       Ubuntu/Debian:  sudo systemctl enable --now clamav-freshclam"
    echo "       Fedora/RHEL:    sudo systemctl enable --now clamav-freshclam"
    echo "       Arch/openSUSE:  sudo systemctl enable --now freshclam"
fi

echo -e "\n${BOLD}${GREEN}Installation Complete!${NC}"
echo -e "To enable and start the Clamguard service:"
echo -e "  ${CYAN}sudo systemctl enable --now ${SERVICE_NAME}${NC}"
echo -e "To view logs:"
echo -e "  ${CYAN}sudo journalctl -u ${SERVICE_NAME} -f${NC}"
