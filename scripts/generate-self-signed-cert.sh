#!/usr/bin/env bash
set -euo pipefail

CERT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../nginx/certs" && pwd)"
VM_IP="${1:-$(hostname -I | awk '{print $1}')}"

if [[ -z "${VM_IP}" ]]; then
    echo "Usage: $0 <vm-ip>" >&2
    exit 1
fi

mkdir -p "${CERT_DIR}"

openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout "${CERT_DIR}/wynara.key" \
    -out "${CERT_DIR}/wynara.crt" \
    -days 365 \
    -subj "/CN=${VM_IP}" \
    -addext "subjectAltName=IP:${VM_IP}"

chmod 600 "${CERT_DIR}/wynara.key"
chmod 644 "${CERT_DIR}/wynara.crt"
echo "Generated a self-signed certificate for ${VM_IP} in nginx/certs/"
