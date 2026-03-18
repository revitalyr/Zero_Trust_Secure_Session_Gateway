# Zero Trust Secure Session Gateway - Demo Examples

This directory contains demonstration scripts and examples to showcase the Zero Trust Secure Session Gateway functionality.

## 🚀 Quick Start Demo

### Option 1: Automated Demo Script

The easiest way to see the gateway in action is to run the automated demo script:

```bash
# Make the demo script executable
chmod +x examples/demo_script.sh

# Run the full demo
./examples/demo_script.sh
```

This script will:
1. ✅ Check dependencies and build the project
2. 🔐 Generate test TLS certificates
3. 🌐 Start the gateway server
4. 👥 Demonstrate authentication with different users
5. 🎯 Show session creation for various services
6. 📊 Display server status and security statistics

### Option 2: Interactive Menu

Run the demo with an interactive menu:

```bash
./examples/demo_script.sh
```

This will show a menu with options to:
- Run the full automated demo
- Start only the server
- Run the Python client demo
- Show server status
- Exit

### Option 3: Python Client Demo

Use the Python client to interact with a running gateway:

```bash
# Start the gateway first (in another terminal)
# On Linux/macOS:
./build/bin/zerossg_gateway start examples/config.json
# Or with YAML configuration:
./build/bin/zerossg_gateway start examples/config.yaml

# On Windows:
.\build\bin\zerossg_gateway.exe start examples\config.json
# Or with YAML configuration:
.\build\bin\zerossg_gateway.exe start examples\config.yaml

# Run the Python client demo
python3 examples/demo_client.py --demo basic
```

Available demo types:
- `basic`: Basic authentication and session workflow
- `roles`: Role-based access control demonstration
- `security`: Security features demonstration

## 📋 Demo Scenarios

### 1. Basic Authentication Workflow

Demonstrates the complete workflow:
1. **Authentication**: Login with username/password
2. **Session Creation**: Request access to a target service
3. **Proxy Connection**: Establish secure proxy connection
4. **Logout**: Clean termination of session

```python
# Python client example
client = GatewayClient()
client.authenticate("admin", "admin123")
client.create_session("ssh")
client.start_proxy(30)  # 30 seconds
client.logout()
```

### 2. Role-Based Access Control

Shows how different user roles have different access permissions:

| User | Role | SSH Access | Web Admin | Database |
|-------|-------|------------|------------|----------|
| admin | admin | ✅ | ✅ | ✅ |
| operator | operator | ✅ | ✅ | ❌ |
| viewer | viewer | ❌ | ✅ | ❌ |

### 3. Security Features Demonstration

Tests various security controls:
- **Invalid Authentication**: Rejects wrong credentials
- **Unauthorized Access**: Blocks requests without authentication
- **Rate Limiting**: Prevents brute force attacks
- **Session Security**: Validates session tokens

## 🔧 Configuration

### Demo Configuration Files

#### `config.json`
```json
{
  "server": {
    "listen_address": "0.0.0.0",
    "listen_port": 8443,
    "tls_cert_file": "certs/server.crt",
    "tls_key_file": "certs/server.key"
  },
  "target_services": {
    "ssh": {
      "host": "internal-ssh-server",
      "port": 22,
      "allowed_roles": ["admin", "operator"]
    },
    "web-admin": {
      "host": "internal-web-server", 
      "port": 443,
      "allowed_roles": ["admin", "operator", "viewer"]
    }
  }
}
```

#### `config.yaml`
```yaml
# Zero Trust Secure Session Gateway Configuration
server:
  listen_address: "0.0.0.0"
  listen_port: 8443
  tls_cert_file: "certs/server.crt"
  tls_key_file: "certs/server.key"

target_services:
  ssh:
    host: "internal-ssh-server"
    port: 22
    tls_enabled: false
    allowed_roles:
      - "admin"
      - "operator"
  
  web-admin:
    host: "internal-web-server"
    port: 443
    tls_enabled: true
    allowed_roles:
      - "admin"
      - "operator"
      - "viewer"
```

Both JSON and YAML formats are fully supported with identical functionality.

### Test Certificates

The demo generates self-signed certificates for testing:
- `certs/server.crt` - Server certificate
- `certs/server.key` - Server private key

⚠️ **Security Note**: These are for demonstration only. Use proper certificates in production!

## 🐳 Docker Demo

### Using Docker Compose

The easiest way to run the complete demo environment:

```bash
# Start the entire stack (gateway + monitoring)
docker-compose up -d

# View logs
docker-compose logs -f zerossg-gateway

# Stop the demo
docker-compose down
```

This includes:
- **Gateway Server**: The main Zero Trust gateway
- **Internal Services**: Mock SSH, web, database, and API servers
- **Monitoring**: Prometheus + Grafana for metrics
- **Networking**: Isolated network for security

### Standalone Docker

Build and run just the gateway:

```bash
# Build the Docker image
docker build -t zerossg-gateway .

# Run the gateway
docker run -p 8443:8443 \
  -v $(pwd)/examples/config.json:/app/config/config.json:ro \
  -v $(pwd)/certs:/app/certs:ro \
  zerossg-gateway
```

## 📊 Monitoring the Demo

### Access Monitoring Interfaces

When using Docker Compose, access these interfaces:

- **Gateway**: https://localhost:8443
- **Prometheus**: http://localhost:9090
- **Grafana**: http://localhost:3000 (admin/admin)

### Log Files

Monitor the gateway through log files:

```bash
# View main logs
tail -f logs/zerossg.log

# View security events
tail -f logs/security.log

# View audit trail
tail -f logs/audit.log
```

## 🧪 Testing Different Scenarios

### Testing Authentication

```bash
# Test with curl
curl -k -X POST https://localhost:8443 \
  -H "Content-Type: application/json" \
  -d '{"type":"login","username":"admin","password":"admin123"}'
```

### Testing Session Creation

```bash
# First get auth token, then create session
TOKEN=$(curl -k -s -X POST https://localhost:8443 \
  -H "Content-Type: application/json" \
  -d '{"type":"login","username":"admin","password":"admin123"}' | \
  jq -r '.data.token')

curl -k -X POST https://localhost:8443 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"type":"session","target_service":"ssh"}'
```

### Testing Different Users

| Username | Password | Role | Access Level |
|----------|----------|-------|-------------|
| admin | admin123 | admin | Full access |
| operator | operator123 | operator | Operational access |
| viewer | viewer123 | viewer | Read-only access |

## 🔍 Troubleshooting

### Common Issues

**Port 8443 already in use:**
```bash
# Find what's using the port
netstat -tulpn | grep :8443
# Or change the port in config.json
```

**Certificate errors:**
```bash
# Regenerate certificates
openssl genrsa -out certs/server.key 2048
openssl req -new -key certs/server.key -out certs/server.csr -subj "/CN=localhost"
openssl x509 -req -days 365 -in certs/server.csr -signkey certs/server.key -out certs/server.crt
```

**Build failures:**
```bash
# On Linux/macOS:
rm -rf build
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# On Windows (from Developer Command Prompt):
rmdir /s build
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=<vcpkg-root>\scripts\buildsystems\vcpkg.cmake
cmake --build . --config Release
```

**Connection refused:**
- Make sure the gateway is running
- Check the firewall settings
- Verify the port and address in config

### Debug Mode

Enable debug logging for troubleshooting:

```json
{
  "logging": {
    "level": "debug",
    "enable_console_output": true,
    "enable_file_output": true
  }
}
```

## 🎯 Learning Objectives

After running these demos, you should understand:

1. **Zero Trust Principles**: How the gateway implements "never trust, always verify"
2. **Authentication Flow**: Username/password → JWT token → Session creation
3. **Authorization**: Role-based access control in action
4. **Security Controls**: Rate limiting, brute force protection
5. **Session Management**: Secure session lifecycle
6. **Proxy Functionality**: Secure traffic forwarding
7. **Monitoring**: Comprehensive logging and metrics
8. **Configuration**: Flexible JSON/YAML configuration
9. **Containerization**: Docker deployment patterns
10. **Enterprise Features**: Production-ready capabilities

## 📚 Next Steps

After the demo:

1. **Read the Architecture**: `docs/architecture.md`
2. **Study Security Model**: `docs/security_model.md`
3. **Review Threat Model**: `docs/threat_model.md`
4. **Examine Source Code**: Review the implementation
5. **Run Unit Tests**: `ctest` in build directory
6. **Customize Configuration**: Modify for your environment
7. **Deploy to Production**: Use Docker or Kubernetes
8. **Extend Functionality**: Add new features or integrations

## 🤝 Contributing

Have ideas for improving the demo?

1. Fork the repository
2. Create a feature branch
3. Add your improvements
4. Submit a pull request

We welcome contributions for:
- New demo scenarios
- Additional client examples
- Better monitoring dashboards
- Enhanced security tests
- Performance benchmarks
