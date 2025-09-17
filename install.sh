#!/bin/bash
# Supply Chain Scanner Installation Script

set -e

echo "🔧 Installing Supply Chain Security Scanner..."

# Check Python version
python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
required_version="3.8"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "❌ Error: Python $required_version or higher is required. Found: $python_version"
    exit 1
fi

echo "✅ Python $python_version detected"

# Install from PyPI (when available)
if command -v pip3 &> /dev/null; then
    echo "📦 Installing from PyPI..."
    pip3 install supply-chain-scanner
    echo "✅ Installation completed!"
    echo ""
    echo "🚀 Quick start:"
    echo "  supply-chain-scanner --provider gitlab --token YOUR_TOKEN"
    echo "  supply-chain-scanner --provider github --token YOUR_TOKEN"
else
    # Local installation
    echo "📦 Installing dependencies..."
    pip3 install -r requirements.txt
    
    echo "✅ Installation completed!"
    echo ""
    echo "🚀 Quick start:"
    echo "  python3 scanner.py --provider gitlab --token YOUR_TOKEN"
    echo "  python3 scanner.py --provider github --token YOUR_TOKEN"
fi

echo ""
echo "📚 Documentation: https://github.com/security-community/supply-chain-scanner"
echo "🐛 Issues: https://github.com/security-community/supply-chain-scanner/issues"
echo "💬 Discussions: https://github.com/security-community/supply-chain-scanner/discussions"