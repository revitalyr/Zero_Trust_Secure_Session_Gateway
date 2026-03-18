#!/bin/bash

# Zero Trust Secure Session Gateway Demo Script
# This script sets up and runs a complete demonstration of the gateway

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
GATEWAY_HOST="localhost"
GATEWAY_PORT="8443"
CONFIG_FILE="examples/config.json"
LOG_DIR="logs"

# Functions
print_banner() {
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║           Zero Trust Secure Session Gateway - Demo              ║"
    echo "║                                                                ║"
    echo "║  This demo will start the gateway server and show various      ║"
    echo "║  security and authentication features in action.             ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_step() {
    echo -e "${BLUE}📋 Step $1: $2${NC}"
    echo -e "${BLUE}$(printf '─%.0s' {1..50})${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${CYAN}ℹ️  $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

# Check dependencies
check_dependencies() {
    print_step "1" "Checking Dependencies"
    
    # Check if required directories exist
    if [ ! -f "CMakeLists.txt" ]; then
        print_error "CMakeLists.txt not found. Please run from project root."
        exit 1
    fi
    
    if [ ! -f "$CONFIG_FILE" ]; then
        print_error "Configuration file not found: $CONFIG_FILE"
        exit 1
    fi
    
    # Check for build tools
    if ! command -v cmake &> /dev/null; then
        print_error "CMake is required but not installed."
        exit 1
    fi
    
    if ! command -v make &> /dev/null; then
        print_error "Make is required but not installed."
        exit 1
    fi
    
    print_success "All dependencies found"
}

# Build the project
build_project() {
    print_step "2" "Building Project"
    
    # Create build directory
    mkdir -p build
    cd build
    
    # Configure with CMake
    print_info "Configuring with CMake..."
    cmake .. -DCMAKE_BUILD_TYPE=Release
    
    # Build
    print_info "Building project..."
    make -j$(nproc)
    
    cd ..
    print_success "Project built successfully"
}

# Generate test certificates
generate_certificates() {
    print_step "3" "Generating Test Certificates"
    
    mkdir -p certs
    
    # Generate private key
    openssl genrsa -out certs/server.key 2048
    
    # Generate certificate signing request
    openssl req -new -key certs/server.key -out certs/server.csr -subj "/C=US/ST=State/L=City/O=ZeroTrust/OU=Gateway/CN=localhost"
    
    # Generate self-signed certificate
    openssl x509 -req -days 365 -in certs/server.csr -signkey certs/server.key -out certs/server.crt
    
    print_success "Test certificates generated in certs/"
}

# Start the gateway server
start_gateway() {
    print_step "4" "Starting Gateway Server"
    
    # Create log directory
    mkdir -p "$LOG_DIR"
    
    # Start server in background
    print_info "Starting Zero Trust Gateway on port $GATEWAY_PORT..."
    ./build/zerossg_gateway start "$CONFIG_FILE" > "$LOG_DIR/gateway.log" 2>&1 &
    GATEWAY_PID=$!
    
    # Wait for server to start
    sleep 3
    
    # Check if server is running
    if kill -0 $GATEWAY_PID 2>/dev/null; then
        print_success "Gateway server started (PID: $GATEWAY_PID)"
    else
        print_error "Failed to start gateway server"
        exit 1
    fi
}

# Run authentication demo
run_auth_demo() {
    print_step "5" "Running Authentication Demo"
    
    print_info "Testing authentication with different users..."
    
    # Test admin login
    echo -e "${YELLOW}Testing admin login...${NC}"
    curl -k -X POST "https://$GATEWAY_HOST:$GATEWAY_PORT" \
         -H "Content-Type: application/json" \
         -d '{"type":"login","username":"admin","password":"admin123"}' \
         2>/dev/null | python3 -m json.tool || echo "Failed to connect"
    
    echo
    
    # Test invalid login
    echo -e "${YELLOW}Testing invalid login...${NC}"
    curl -k -X POST "https://$GATEWAY_HOST:$GATEWAY_PORT" \
         -H "Content-Type: application/json" \
         -d '{"type":"login","username":"invalid","password":"wrong"}' \
         2>/dev/null | python3 -m json.tool || echo "Failed to connect (expected)"
    
    print_success "Authentication demo completed"
}

# Run session demo
run_session_demo() {
    print_step "6" "Running Session Management Demo"
    
    print_info "Testing session creation and management..."
    
    # Create session (this would normally use the token from auth)
    echo -e "${YELLOW}Testing session creation...${NC}"
    curl -k -X POST "https://$GATEWAY_HOST:$GATEWAY_PORT" \
         -H "Content-Type: application/json" \
         -d '{"type":"session","target_service":"ssh"}' \
         2>/dev/null | python3 -m json.tool || echo "Failed to connect"
    
    print_success "Session demo completed"
}

# Show server status
show_status() {
    print_step "7" "Server Status"
    
    print_info "Checking gateway server status..."
    
    # Use CLI to show status
    if [ -f "build/zerossg_gateway" ]; then
        ./build/zerossg_gateway status 2>/dev/null || print_warning "Status check failed"
    fi
    
    # Show log file info
    if [ -f "$LOG_DIR/gateway.log" ]; then
        print_info "Log file: $LOG_DIR/gateway.log"
        print_info "Recent log entries:"
        tail -5 "$LOG_DIR/gateway.log" 2>/dev/null | sed 's/^/  /'
    fi
}

# Show security statistics
show_security_stats() {
    print_step "8" "Security Statistics"
    
    print_info "Security event summary:"
    
    # Count security events in logs
    if [ -f "$LOG_DIR/gateway.log" ]; then
        local failed_logins=$(grep -c "LOGIN_FAILURE" "$LOG_DIR/gateway.log" 2>/dev/null || echo "0")
        local successful_logins=$(grep -c "LOGIN_SUCCESS" "$LOG_DIR/gateway.log" 2>/dev/null || echo "0")
        local security_events=$(grep -c "SECURITY_EVENT" "$LOG_DIR/gateway.log" 2>/dev/null || echo "0")
        
        echo "  Failed login attempts: $failed_logins"
        echo "  Successful logins: $successful_logins"
        echo "  Security events: $security_events"
    fi
    
    print_success "Security statistics displayed"
}

# Cleanup function
cleanup() {
    print_step "9" "Cleanup"
    
    # Stop gateway server
    if [ ! -z "$GATEWAY_PID" ]; then
        print_info "Stopping gateway server..."
        kill $GATEWAY_PID 2>/dev/null || true
        wait $GATEWAY_PID 2>/dev/null || true
        print_success "Gateway server stopped"
    fi
    
    # Clean up build artifacts (optional)
    read -p "Clean build artifacts? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf build
        print_success "Build artifacts cleaned"
    fi
}

# Main demo function
run_demo() {
    print_banner
    
    check_dependencies
    build_project
    generate_certificates
    start_gateway
    
    # Wait a moment for server to fully start
    sleep 2
    
    run_auth_demo
    sleep 1
    run_session_demo
    sleep 1
    show_status
    show_security_stats
    
    print_info "Demo is running. Press Ctrl+C to stop..."
    
    # Keep server running
    trap cleanup EXIT
    while true; do
        sleep 1
    done
}

# Interactive menu
show_menu() {
    echo -e "${CYAN}"
    echo "Zero Trust Gateway Demo Menu"
    echo "=========================="
    echo "1) Run Full Demo"
    echo "2) Start Server Only"
    echo "3) Run Python Client Demo"
    echo "4) Show Server Status"
    echo "5) Exit"
    echo -e "${NC}"
    
    read -p "Choose an option (1-5): " -n 1 -r
    echo
    
    case $REPLY in
        1)
            run_demo
            ;;
        2)
            check_dependencies
            build_project
            generate_certificates
            start_gateway
            trap cleanup EXIT
            while true; do sleep 1; done
            ;;
        3)
            if command -v python3 &> /dev/null; then
                python3 examples/demo_client.py --demo basic
            else
                print_error "Python 3 is required for client demo"
            fi
            ;;
        4)
            if [ -f "build/zerossg_gateway" ]; then
                ./build/zerossg_gateway status
            else
                print_error "Gateway not built. Run option 1 or 2 first."
            fi
            ;;
        5)
            print_info "Goodbye!"
            exit 0
            ;;
        *)
            print_error "Invalid option. Please choose 1-5."
            ;;
    esac
}

# Check if running interactively
if [ -t 0 ]; then
    # Interactive mode
    show_menu
else
    # Non-interactive mode - run full demo
    run_demo
fi
