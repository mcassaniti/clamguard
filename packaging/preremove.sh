#!/bin/sh
set -e

# Stop and disable the service before removing the package
systemctl stop clamguard.service 2>/dev/null || true
systemctl disable clamguard.service 2>/dev/null || true
