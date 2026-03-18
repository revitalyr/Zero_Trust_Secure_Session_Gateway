#!/usr/bin/env python3
"""
Zero Trust Secure Session Gateway Demo Client

This script demonstrates how to interact with the gateway server
including authentication, session creation, and secure proxy connections.
"""

import json
import ssl
import socket
import time
import argparse
from typing import Optional, Dict, Any

class GatewayClient:
    def __init__(self, host: str = "localhost", port: int = 8443):
        self.host = host
        self.port = port
        self.session_id = None
        self.auth_token = None
        self.user_info = None
        
    def connect(self) -> ssl.SSLSocket:
        """Create secure TLS connection to the gateway"""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # For demo only
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_socket = context.wrap_socket(sock, server_hostname=self.host)
        
        try:
            ssl_socket.connect((self.host, self.port))
            print(f"✅ Connected to gateway at {self.host}:{self.port}")
            return ssl_socket
        except Exception as e:
            print(f"❌ Failed to connect: {e}")
            raise
    
    def send_request(self, ssl_socket: ssl.SSLSocket, request: Dict[str, Any]) -> Dict[str, Any]:
        """Send JSON request and receive response"""
        try:
            # Send request
            request_json = json.dumps(request) + "\n\n"
            ssl_socket.send(request_json.encode())
            
            # Receive response
            response_data = b""
            while True:
                chunk = ssl_socket.recv(1024)
                if not chunk:
                    break
                response_data += chunk
                if b"\n\n" in response_data:
                    break
            
            response_json = response_data.decode().strip()
            return json.loads(response_json)
        except Exception as e:
            print(f"❌ Request failed: {e}")
            raise
    
    def authenticate(self, username: str, password: str) -> bool:
        """Authenticate with the gateway"""
        print(f"🔐 Authenticating user: {username}")
        
        request = {
            "type": "login",
            "username": username,
            "password": password
        }
        
        ssl_socket = self.connect()
        try:
            response = self.send_request(ssl_socket, request)
            
            if response.get("status") == "success":
                self.auth_token = response["data"]["token"]
                self.user_info = response["data"]["user"]
                print(f"✅ Authentication successful")
                print(f"   Role: {self.user_info['role']}")
                print(f"   Token: {self.auth_token[:20]}...")
                return True
            else:
                print(f"❌ Authentication failed: {response.get('message')}")
                return False
        finally:
            ssl_socket.close()
    
    def create_session(self, target_service: str) -> bool:
        """Create a session for a target service"""
        if not self.auth_token:
            print("❌ Not authenticated")
            return False
        
        print(f"🎯 Creating session for service: {target_service}")
        
        request = {
            "type": "session",
            "target_service": target_service
        }
        
        ssl_socket = self.connect()
        try:
            response = self.send_request(ssl_socket, request)
            
            if response.get("status") == "success":
                self.session_id = response["data"]["session_id"]
                print(f"✅ Session created successfully")
                print(f"   Session ID: {self.session_id}")
                print(f"   Target: {response['data']['target_service']}")
                return True
            else:
                print(f"❌ Session creation failed: {response.get('message')}")
                return False
        finally:
            ssl_socket.close()
    
    def start_proxy(self, duration: int = 30) -> bool:
        """Start proxy connection for data transfer"""
        if not self.session_id:
            print("❌ No active session")
            return False
        
        print(f"🔄 Starting proxy connection for {duration} seconds")
        
        request = {
            "type": "proxy",
            "session_id": self.session_id
        }
        
        ssl_socket = self.connect()
        try:
            response = self.send_request(ssl_socket, request)
            
            if response.get("status") == "success":
                print(f"✅ Proxy connection established")
                print(f"   Status: {response['data']['status']}")
                
                # Simulate data transfer
                start_time = time.time()
                while time.time() - start_time < duration:
                    try:
                        # Send some test data
                        test_request = {
                            "type": "data",
                            "session_id": self.session_id,
                            "data": "Hello from client"
                        }
                        ssl_socket.send((json.dumps(test_request) + "\n\n").encode())
                        time.sleep(2)
                    except:
                        break
                
                print(f"✅ Proxy session completed")
                return True
            else:
                print(f"❌ Proxy connection failed: {response.get('message')}")
                return False
        finally:
            ssl_socket.close()
    
    def logout(self) -> bool:
        """Logout and terminate session"""
        if not self.auth_token:
            print("❌ Not authenticated")
            return False
        
        print("🚪 Logging out...")
        
        request = {
            "type": "logout"
        }
        
        ssl_socket = self.connect()
        try:
            response = self.send_request(ssl_socket, request)
            
            if response.get("status") == "success":
                print("✅ Logout successful")
                self.auth_token = None
                self.session_id = None
                self.user_info = None
                return True
            else:
                print(f"❌ Logout failed: {response.get('message')}")
                return False
        finally:
            ssl_socket.close()

def print_banner():
    """Print demo banner"""
    print("""
╔══════════════════════════════════════════════════════════════╗
║           Zero Trust Secure Session Gateway - Demo Client          ║
║                                                                ║
║  This demo shows authentication, session creation, and proxy        ║
║  functionality with the Zero Trust gateway server.               ║
╚════════════════════════════════════════════════════════════════╝
    """)

def demo_basic_workflow():
    """Demonstrate basic authentication and session workflow"""
    client = GatewayClient()
    
    try:
        # Step 1: Authentication
        print("\n🔐 Step 1: Authentication")
        print("-" * 50)
        if not client.authenticate("admin", "admin123"):
            print("❌ Demo failed at authentication step")
            return
        
        time.sleep(1)
        
        # Step 2: Create session for SSH service
        print("\n🎯 Step 2: Session Creation")
        print("-" * 50)
        if not client.create_session("ssh"):
            print("❌ Demo failed at session creation step")
            return
        
        time.sleep(1)
        
        # Step 3: Start proxy connection
        print("\n🔄 Step 3: Proxy Connection")
        print("-" * 50)
        if not client.start_proxy(10):
            print("❌ Demo failed at proxy connection step")
            return
        
        time.sleep(1)
        
        # Step 4: Logout
        print("\n🚪 Step 4: Logout")
        print("-" * 50)
        client.logout()
        
        print("\n✅ Demo completed successfully!")
        
    except KeyboardInterrupt:
        print("\n⚠️  Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo failed with error: {e}")

def demo_role_based_access():
    """Demonstrate role-based access control"""
    print("\n👥 Role-Based Access Control Demo")
    print("=" * 50)
    
    # Test different user roles
    users = [
        ("admin", "admin123", "Admin User"),
        ("operator", "operator123", "Operator User"),
        ("viewer", "viewer123", "Viewer User")
    ]
    
    services = ["ssh", "web-admin", "database"]
    
    for username, password, user_type in users:
        print(f"\n👤 Testing {user_type}: {username}")
        print("-" * 30)
        
        client = GatewayClient()
        
        if client.authenticate(username, password):
            for service in services:
                print(f"  🎯 Testing access to {service}...")
                if client.create_session(service):
                    client.logout()
                    print(f"    ✅ Access GRANTED")
                else:
                    print(f"    ❌ Access DENIED")
                time.sleep(0.5)

def demo_security_features():
    """Demonstrate security features"""
    print("\n🛡️  Security Features Demo")
    print("=" * 50)
    
    client = GatewayClient()
    
    # Test invalid authentication
    print("\n🔐 Testing invalid authentication...")
    print("-" * 40)
    if not client.authenticate("invalid", "wrong"):
        print("✅ Invalid authentication properly rejected")
    
    time.sleep(1)
    
    # Test session without authentication
    print("\n🎯 Testing session creation without auth...")
    print("-" * 40)
    if not client.create_session("ssh"):
        print("✅ Unauthorized session request properly rejected")
    
    time.sleep(1)
    
    # Test valid authentication
    print("\n🔐 Testing valid authentication...")
    print("-" * 40)
    if client.authenticate("admin", "admin123"):
        print("✅ Valid authentication successful")

def main():
    """Main demo function"""
    parser = argparse.ArgumentParser(description="Zero Trust Gateway Demo Client")
    parser.add_argument("--host", default="localhost", help="Gateway host")
    parser.add_argument("--port", type=int, default=8443, help="Gateway port")
    parser.add_argument("--demo", choices=["basic", "roles", "security"], 
                       default="basic", help="Demo type to run")
    
    args = parser.parse_args()
    
    print_banner()
    
    print(f"🌐 Connecting to gateway at {args.host}:{args.port}")
    print(f"📋 Demo type: {args.demo}")
    print()
    
    if args.demo == "basic":
        demo_basic_workflow()
    elif args.demo == "roles":
        demo_role_based_access()
    elif args.demo == "security":
        demo_security_features()
    
    print("\n🎉 Demo finished!")

if __name__ == "__main__":
    main()
