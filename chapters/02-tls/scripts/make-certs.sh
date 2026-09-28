#!/usr/bin/env bash
# 02 · Build the lab PKI with the system openssl into chapters/02-tls/certs/.
#
# Two independent certificate authorities. Same shapes, different signers:
#
#   Lab CA   → server (CN=localhost, SAN DNS:localhost, IP:127.0.0.1)  → client (CN=alice)
#   Rogue CA → rogue-server (same name, same SAN)                       → rogue-client (also CN=alice)
#
# Idempotent: running it again replaces everything. Certificates live 1 day;
# nothing generated here should outlive the lesson. `src/certs.ts` does the
# same in TypeScript for the tests; keep the two in sync.
#
# Why a config/ext file and not only `-addext`: `-addext` needs OpenSSL 1.1.1+
# and `x509 -req` does not accept it at all. `-extfile` works everywhere, and
# it puts every extension in one readable place.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${1:-$HERE/../certs}"
DAYS=1

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl not found on PATH. Install it (brew install openssl / apt install openssl) and retry." >&2
  exit 1
fi

mkdir -p "$OUT"
cd "$OUT"
echo "02 · TLS · generating the lab PKI into $(pwd) with $(openssl version)"
echo

# `openssl req` wants a config with a distinguished_name section even when the
# subject comes from -subj. [ca_ext] holds the extensions of a root: CA:TRUE is
# what lets a certificate sign other certificates; pathlen:0 forbids intermediates.
cat > req.cnf <<'EOF'
[req]
distinguished_name = dn
prompt = no

[dn]
CN = placeholder-overridden-by-subj

[ca_ext]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF

# Server certificate: the client checks the hostname against subjectAltName
# (RFC 6125), never against CN. extendedKeyUsage=serverAuth: this key is for
# BEING a server; a client cert cannot be turned around to impersonate one.
cat > server.ext <<'EOF'
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost, IP:127.0.0.1, IP:::1
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid, issuer
EOF

# Client certificate: clientAuth only, no SAN needed; identity is the CN.
cat > client.ext <<'EOF'
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid, issuer
EOF

# Random 128-bit serial. Serials must be unique per CA (RFC 5280); browsers reject reuse.
serial() { echo "0x$(openssl rand -hex 16)"; }

# P-256 private key: small, fast, what most of the public web uses today.
make_key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$1-key.pem" 2>/dev/null; }

# A root signs its own certificate. Nobody vouches for a root: verifiers CHOOSE to trust it.
make_ca() { # name cn
  make_key "$1"
  openssl req -x509 -new -key "$1-key.pem" -out "$1.pem" -days "$DAYS" -subj "/CN=$2" \
    -config req.cnf -extensions ca_ext -set_serial "$(serial)" 2>/dev/null
  echo "  $1-key.pem      private key of '$2' (the crown jewels of a CA; never leaves the CA)"
  echo "  $1.pem          self-signed root certificate of '$2' (public; this is what verifiers install)"
}

# Issue: the subject makes a key and a signing request (CSR); the CA signs the
# request plus the extensions IT decides. The private key never leaves the subject.
issue() { # name cn ca extfile description
  make_key "$1"
  openssl req -new -key "$1-key.pem" -out "$1.csr" -subj "/CN=$2" -config req.cnf 2>/dev/null
  openssl x509 -req -in "$1.csr" -CA "$3.pem" -CAkey "$3-key.pem" -set_serial "$(serial)" \
    -days "$DAYS" -extfile "$4" -out "$1.pem" 2>/dev/null
  echo "  $1-key.pem  private key of $5"
  echo "  $1.pem      certificate of $5, signed by $3.pem"
}

echo "lab CA and what it signed:"
make_ca ca "Lab CA"
issue server localhost ca server.ext "the server (CN=localhost)"
issue client alice ca client.ext "the client alice (CN=alice)"
echo
echo "rogue CA and what it signed (same names, different signer; the clients must reject all of it):"
make_ca rogue-ca "Rogue CA"
issue rogue-server localhost rogue-ca server.ext "an impostor server (CN=localhost)"
issue rogue-client alice rogue-ca client.ext "an impostor client (also CN=alice)"
rm -f ./*.csr

echo
echo "the server certificate, as openssl reads it:"
openssl x509 -in server.pem -noout -subject -issuer -dates -ext subjectAltName | sed 's/^/  /'
echo
echo "verify the chain the way a client will:"
echo -n "  server.pem against ca.pem:        "; openssl verify -CAfile ca.pem server.pem
echo -n "  rogue-server.pem against ca.pem:  "; openssl verify -CAfile ca.pem rogue-server.pem 2>&1 | tail -1 || true
echo
echo "next: npm run 02:server, then npm run 02:client in another terminal"
