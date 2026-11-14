#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"

echo "========================================================================="
echo "Building Antora Documentation Site for Incert OCSP Subsystem..."
echo "========================================================================="

npx -y -p @antora/cli -p @antora/site-generator antora antora-playbook.yml

echo ""
echo "Documentation build complete!"
echo "Open build/site/index.html in your browser or serve via: npx serve build/site"
echo "========================================================================="

