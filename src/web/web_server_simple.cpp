// Simple web server implementation with real HTTP handling
module;

#include <iostream>
#include <sstream>
#include <thread>
#include <vector>
#include <map>
#include <chrono>
#include <regex>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#endif

import zerossg.constants;
module zerossg.web.web_server;

namespace zerossg {

// Port checking implementation
bool WebServer::is_port_available(const String& address, int port) {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(WINSOCK_VERSION_REQUESTED, &wsaData) != WINSOCK_VERSION_SUCCESS) {
        return false;
    }
    
    SOCKET sock = socket(SOCKET_FAMILY_IPV4, SOCKET_TYPE_TCP, SOCKET_PROTOCOL_TCP);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return false;
    }
    
    sockaddr_in serverAddr;
    serverAddr.sin_family = SOCKET_FAMILY_IPV4;
    serverAddr.sin_port = htons(port);
    
    if (address == DEFAULT_LOCALHOST || address == DEFAULT_LOOPBACK_IP) {
        serverAddr.sin_addr.s_addr = inet_addr(DEFAULT_LOOPBACK_IP);
    } else {
        serverAddr.sin_addr.s_addr = inet_addr(address.c_str());
    }
    
    // Try to bind to the port
    int result = bind(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    
    closesocket(sock);
    WSACleanup();
    
    return result == 0;
#else
    int sock = socket(SOCKET_FAMILY_IPV4, SOCKET_TYPE_TCP, SOCKET_PROTOCOL_TCP);
    if (sock < 0) {
        return false;
    }
    
    sockaddr_in serverAddr;
    serverAddr.sin_family = SOCKET_FAMILY_IPV4;
    serverAddr.sin_port = htons(port);
    
    if (address == DEFAULT_LOCALHOST || address == DEFAULT_LOOPBACK_IP) {
        serverAddr.sin_addr.s_addr = inet_addr(DEFAULT_LOOPBACK_IP);
    } else {
        serverAddr.sin_addr.s_addr = inet_addr(address.c_str());
    }
    
    int result = bind(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    close(sock);
    
    return result == 0;
#endif
}

bool WebServer::is_port_available(int port) {
    return is_port_available(DEFAULT_LOCALHOST, port);
}

// Simple HTTP response helper
String create_http_response(int status, const String& content_type, const String& body) {
    std::ostringstream response;
    response << HTTP_VERSION_1_1 << " " << status << " OK\r\n";
    response << HTTP_HEADER_CONTENT_TYPE << ": " << content_type << "\r\n";
    response << HTTP_HEADER_CONTENT_LENGTH << ": " << body.length() << "\r\n";
    response << "Connection: close\r\n";
    response << "\r\n";
    response << body;
    return response.str();
}

// Parse HTTP request
String parse_http_path(const String& request) {
    std::regex path_regex(R"(GET\s+([^\s]+)\s+HTTP)");
    std::smatch match;
    
    if (std::regex_search(request, match, path_regex)) {
        return match[1].str();
    }
    
    return "/";
}

Result<void> WebServer::start(const String& address, int port) {
    if (m_running) {
        return std::unexpected("Server is already running");
    }
    
    // Check if port is available
    if (!is_port_available(address, port)) {
        return std::unexpected("Port " + std::to_string(port) + " is already in use on " + address);
    }
    
    m_address = address;
    m_port = port;
    
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(WINSOCK_VERSION_REQUESTED, &wsaData) != WINSOCK_VERSION_SUCCESS) {
        return std::unexpected("Failed to initialize WinSock");
    }
#endif
    
    std::cout << "Starting web server on " << address << ":" << port << "\n";
    std::cout << "Web interface available at: http://" << address << ":" << port << "\n";
    
    m_running = true;
    
    // Start actual HTTP server in separate thread
    std::thread([this]() {
        run_http_server();
    }).detach();
    
    return {};
}

void WebServer::run_http_server() {
#ifdef _WIN32
    SOCKET listenSocket = socket(SOCKET_FAMILY_IPV4, SOCKET_TYPE_TCP, SOCKET_PROTOCOL_TCP);
    if (listenSocket == INVALID_SOCKET) {
        std::cerr << "Failed to create socket\n";
        return;
    }
    
    sockaddr_in serverAddr;
    serverAddr.sin_family = SOCKET_FAMILY_IPV4;
    serverAddr.sin_port = htons(m_port);
    serverAddr.sin_addr.s_addr = inet_addr(DEFAULT_LOOPBACK_IP);
    
    if (bind(listenSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Bind failed\n";
        closesocket(listenSocket);
        return;
    }
    
    if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Listen failed\n";
        closesocket(listenSocket);
        return;
    }
    
    std::cout << "HTTP server listening on port " << m_port << "\n";
    
    while (m_running) {
        SOCKET clientSocket = accept(listenSocket, NULL, NULL);
        if (clientSocket == INVALID_SOCKET) {
            if (m_running) {
                std::cerr << "Accept failed\n";
            }
            continue;
        }
        
        // Handle client request
        handle_client(clientSocket);
    }
    
    closesocket(listenSocket);
    WSACleanup();
#else
    int listenSocket = socket(SOCKET_FAMILY_IPV4, SOCKET_TYPE_TCP, SOCKET_PROTOCOL_TCP);
    if (listenSocket < 0) {
        std::cerr << "Failed to create socket\n";
        return;
    }
    
    sockaddr_in serverAddr;
    serverAddr.sin_family = SOCKET_FAMILY_IPV4;
    serverAddr.sin_port = htons(m_port);
    serverAddr.sin_addr.s_addr = inet_addr(DEFAULT_LOOPBACK_IP);
    
    if (bind(listenSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        std::cerr << "Bind failed\n";
        close(listenSocket);
        return;
    }
    
    if (listen(listenSocket, SOMAXCONN) < 0) {
        std::cerr << "Listen failed\n";
        close(listenSocket);
        return;
    }
    
    std::cout << "HTTP server listening on port " << m_port << "\n";
    
    while (m_running) {
        int clientSocket = accept(listenSocket, NULL, NULL);
        if (clientSocket < 0) {
            if (m_running) {
                std::cerr << "Accept failed\n";
            }
            continue;
        }
        
        // Handle client request
        handle_client(clientSocket);
    }
    
    close(listenSocket);
#endif
}

void WebServer::handle_client(int clientSocket) {
    // Read request
    char buffer[4096];
    int bytesReceived;
    
#ifdef _WIN32
    bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
#else
    bytesReceived = read(clientSocket, buffer, sizeof(buffer) - 1);
#endif
    
    if (bytesReceived <= 0) {
#ifdef _WIN32
        closesocket(clientSocket);
#else
        close(clientSocket);
#endif
        return;
    }
    
    buffer[bytesReceived] = '\0';
    String request(buffer);
    
    // Parse path and route
    String path = parse_http_path(request);
    HttpResponse response = route_request(path);
    
    // Send response
    String httpResponse = create_http_response(response.status_code, response.content_type, response.body);
    
#ifdef _WIN32
    send(clientSocket, httpResponse.c_str(), httpResponse.length(), 0);
    closesocket(clientSocket);
#else
    write(clientSocket, httpResponse.c_str(), httpResponse.length());
    close(clientSocket);
#endif
}

HttpResponse WebServer::route_request(const String& path) {
    if (path == "/" || path.empty()) {
        return handle_root();
    } else if (path == "/status") {
        return handle_status();
    } else if (path == "/config") {
        return handle_config();
    } else if (path == "/users") {
        return handle_users();
    } else if (path == "/sessions") {
        return handle_sessions();
    } else if (path == "/logs") {
        return handle_logs();
    } else {
        return handle_not_found();
    }
}

Result<void> WebServer::stop() {
    if (!m_running) {
        return std::unexpected("Server is not running");
    }
    
    std::cout << "Stopping web server...\n";
    m_running = false;
    
    return {};
}

bool WebServer::is_running() const {
    return m_running;
}

HttpResponse WebServer::handle_root() {
    String html = R"(
<!DOCTYPE html>
<html>
<head>
    <title>Zero Trust Secure Session Gateway</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #2c3e50; color: white; padding: 20px; text-align: center; }
        .nav { background: #34495e; padding: 10px; }
        .nav a { color: white; text-decoration: none; margin: 0 15px; }
        .content { margin: 20px 0; }
        .card { border: 1px solid #ddd; padding: 20px; margin: 10px 0; border-radius: 5px; }
        .status { background: #d4edda; padding: 10px; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Zero Trust Secure Session Gateway</h1>
        <p>Web Management Interface</p>
    </div>
    <div class="nav">
        <a href="/">Home</a>
        <a href="/status">Status</a>
        <a href="/config">Configuration</a>
        <a href="/users">Users</a>
        <a href="/sessions">Sessions</a>
        <a href="/logs">Logs</a>
    </div>
    <div class="content">
        <div class="status">
            <h2>System Status</h2>
            <p>Server Status: <strong>Running</strong></p>
            <p>Active Sessions: <strong>0</strong></p>
            <p>Uptime: <strong>0h 0m 0s</strong></p>
        </div>
        <div class="card">
            <h3>Quick Actions</h3>
            <ul>
                <li><a href="/config">Manage Configuration</a></li>
                <li><a href="/users">Manage Users</a></li>
                <li><a href="/sessions">View Active Sessions</a></li>
                <li><a href="/logs">View System Logs</a></li>
            </ul>
        </div>
    </div>
</body>
</html>
    )";
    
    return HttpResponse(200, "text/html", html);
}

HttpResponse WebServer::handle_status() {
    String json = get_status_json();
    return make_json_response(json);
}

HttpResponse WebServer::handle_config() {
    String html = R"(
<!DOCTYPE html>
<html>
<head>
    <title>Configuration - Zero Trust Gateway</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .form-group { margin: 15px 0; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input, textarea, select { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        button { background: #3498db; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #2980b9; }
    </style>
</head>
<body>
    <h2>Configuration Management</h2>
    <form>
        <div class="form-group">
            <label>Server Port:</label>
            <input type="number" value="8080" />
        </div>
        <div class="form-group">
            <label>Log Level:</label>
            <select>
                <option>DEBUG</option>
                <option selected>INFO</option>
                <option>WARN</option>
                <option>ERROR</option>
            </select>
        </div>
        <div class="form-group">
            <label>Max Sessions:</label>
            <input type="number" value="100" />
        </div>
        <div class="form-group">
            <label>Session Timeout (minutes):</label>
            <input type="number" value="30" />
        </div>
        <button type="submit">Save Configuration</button>
    </form>
</body>
</html>
    )";
    
    return HttpResponse(200, "text/html", html);
}

HttpResponse WebServer::handle_users() {
    String html = R"(
<!DOCTYPE html>
<html>
<head>
    <title>Users - Zero Trust Gateway</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
        .btn { background: #3498db; color: white; padding: 6px 12px; text-decoration: none; border-radius: 3px; }
        .btn-danger { background: #e74c3c; }
    </style>
</head>
<body>
    <h2>User Management</h2>
    <p><a href="/users/add" class="btn">Add New User</a></p>
    <table>
        <thead>
            <tr>
                <th>Username</th>
                <th>Role</th>
                <th>Status</th>
                <th>Last Login</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td>admin</td>
                <td>Administrator</td>
                <td>Active</td>
                <td>Never</td>
                <td>
                    <a href="/users/edit/admin" class="btn">Edit</a>
                    <a href="/users/delete/admin" class="btn btn-danger">Delete</a>
                </td>
            </tr>
        </tbody>
    </table>
</body>
</html>
    )";
    
    return HttpResponse(200, "text/html", html);
}

HttpResponse WebServer::handle_sessions() {
    String html = R"(
<!DOCTYPE html>
<html>
<head>
    <title>Sessions - Zero Trust Gateway</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
        .btn { background: #e74c3c; color: white; padding: 6px 12px; text-decoration: none; border-radius: 3px; }
        .status-active { color: #27ae60; font-weight: bold; }
        .status-expired { color: #e74c3c; }
    </style>
</head>
<body>
    <h2>Active Sessions</h2>
    <table>
        <thead>
            <tr>
                <th>Session ID</th>
                <th>User</th>
                <th>IP Address</th>
                <th>Start Time</th>
                <th>Status</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td colspan="6" style="text-align: center; color: #666;">No active sessions</td>
            </tr>
        </tbody>
    </table>
</body>
</html>
    )";
    
    return HttpResponse(200, "text/html", html);
}

HttpResponse WebServer::handle_logs() {
    String html = R"(
<!DOCTYPE html>
<html>
<head>
    <title>Logs - Zero Trust Gateway</title>
    <style>
        body { font-family: monospace; margin: 40px; }
        .log-entry { margin: 2px 0; padding: 5px; border-left: 3px solid #ddd; }
        .log-info { border-left-color: #3498db; }
        .log-warn { border-left-color: #f39c12; }
        .log-error { border-left-color: #e74c3c; }
        .timestamp { color: #666; margin-right: 10px; }
    </style>
</head>
<body>
    <h2>System Logs</h2>
    <div class="log-entry log-info">
        <span class="timestamp">2024-01-01 10:00:00</span>
        <span>[INFO]</span> Web server started on localhost:8080
    </div>
    <div class="log-entry log-info">
        <span class="timestamp">2024-01-01 10:00:01</span>
        <span>[INFO]</span> Web interface initialized
    </div>
    <div class="log-entry log-warn">
        <span class="timestamp">2024-01-01 10:00:02</span>
        <span>[WARN]</span> No active sessions found
    </div>
</body>
</html>
    )";
    
    return HttpResponse(200, "text/html", html);
}

String WebServer::get_status_json() const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"server\": {\n";
    oss << "    \"status\": \"" << (m_running ? "running" : "stopped") << "\",\n";
    oss << "    \"address\": \"" << m_address << "\",\n";
    oss << "    \"port\": " << m_port << ",\n";
    oss << "    \"uptime\": \"0h 0m 0s\"\n";
    oss << "  },\n";
    oss << "  \"sessions\": {\n";
    oss << "    \"active\": 0,\n";
    oss << "    \"total\": 0\n";
    oss << "  },\n";
    oss << "  \"system\": {\n";
    oss << "    \"memory_usage\": \"N/A\",\n";
    oss << "    \"cpu_usage\": \"N/A\"\n";
    oss << "  }\n";
    oss << "}";
    return oss.str();
}

String WebServer::get_config_json() const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"server\": {\n";
    oss << "    \"port\": " << m_port << ",\n";
    oss << "    \"address\": \"" << m_address << "\"\n";
    oss << "  },\n";
    oss << "  \"logging\": {\n";
    oss << "    \"level\": \"INFO\",\n";
    oss << "    \"file\": \"logs/zerossg.log\"\n";
    oss << "  },\n";
    oss << "  \"security\": {\n";
    oss << "    \"session_timeout\": 30,\n";
    oss << "    \"max_sessions\": 100\n";
    oss << "  }\n";
    oss << "}";
    return oss.str();
}

HttpResponse WebServer::handle_not_found() {
    String html = R"(
<!DOCTYPE html>
<html>
<head>
    <title>404 - Not Found</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; text-align: center; }
        .error { color: #e74c3c; font-size: 48px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="error">404</div>
    <h1>Page Not Found</h1>
    <p>The requested page could not be found.</p>
    <p><a href="/">Return to Home</a></p>
</body>
</html>
    )";
    
    return HttpResponse(404, "text/html", html);
}

HttpResponse WebServer::make_json_response(const String& json) {
    return HttpResponse(200, "application/json", json);
}

HttpResponse WebServer::make_html_response(const String& html) {
    return HttpResponse(200, "text/html", html);
}

std::unique_ptr<WebServer> create_web_server() {
    return std::make_unique<WebServer>();
}

} // namespace zerossg
