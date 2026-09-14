#!/bin/sh
set -e

# Reload systemd to recognize the newly installed or updated service
systemctl daemon-reload || true
