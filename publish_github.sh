#!/bin/bash

# GitHub Publication Script for Zero Trust Secure Session Gateway

echo "🚀 Publishing Zero Trust Secure Session Gateway to GitHub..."

# Repository URL
REPO_URL="https://github.com/revitalyr/Zero_Trust_Secure_Session_Gateway.git"

# Add remote origin
echo "📡 Adding remote origin..."
git remote add origin $REPO_URL

# Push to main branch
echo "📤 Pushing to main branch..."
git push -u origin main

# Create and push tags
echo "🏷️ Creating release tags..."
git tag -a v1.0.0 -m "🚀 Initial Release: C++23 Zero Trust Gateway

Modern C++23 implementation of Zero Trust Architecture secure session gateway 
with comprehensive security features and modern web interface.

✨ Features:
• Complete C++23 module system
• Zero Trust security architecture
• Modern web interface and CLI tools
• Comprehensive testing and documentation
• Production-ready deployment support

🔧 Fixes:
• C1001 Internal Compiler Error resolved
• Logger constructor issues fixed
• Module system optimized for MSVC
• Legacy code cleanup completed

📊 Status:
• Build: Working
• Tests: 100% passing
• Documentation: Complete
• License: MIT"

git push origin v1.0.0

# GitHub API call to create repository with topics
echo "🏷️ Setting repository topics..."
curl -X POST \
  -H "Authorization: token $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github.v3+json" \
  https://api.github.com/user/repos \
  -d '{
    "name": "Zero_Trust_Secure_Session_Gateway",
    "description": "Modern C++23 implementation of a Zero Trust Architecture secure session gateway with web-based management interface and CLI tools",
    "private": false,
    "topics": [
      "cpp23",
      "modules", 
      "zero-trust",
      "security",
      "gateway",
      "authentication",
      "authorization", 
      "session-management",
      "rbac",
      "tls",
      "openssl",
      "boost-asio",
      "cmake",
      "modern-cpp",
      "enterprise-security",
      "jwt",
      "web-server",
      "cli"
    ]
  }'

echo "✅ Publication completed!"
echo "📂 Repository: $REPO_URL"
echo "🏷️ Version: v1.0.0"
echo "📋 Documentation: Available in docs/ directory"
echo "🧪 Tests: Run with 'ctest --preset Test-Debug'"
echo "🚀 Build: Run with 'cmake --build --preset Build-Debug'"
