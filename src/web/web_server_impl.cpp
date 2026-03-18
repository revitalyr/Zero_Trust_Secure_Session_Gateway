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

import zerossg.web.web_server;
import zerossg.constants;

export namespace zerossg {

// Port checking implementation
bool WebServer::is_port_available(const String& address, int port) {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return false;
    }
    
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return false;
    }
    
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
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
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        return false;
    }
    
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
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
    
    std::cout << "Starting web server on " << address << ":" << port << "\n";
    std::cout << "Web interface available at: http://" << address << ":" << port << "\n";
    
    m_running = true;
    
    return {};
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

// HTTP handlers
HttpResponse WebServer::handle_root() {
    String html = R"(
<!DOCTYPE html>
<html>
<head>
    <title>Zero Trust Secure Session Gateway</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            margin: 40px; 
        }
        .header { 
            background: #2c3e50; 
            color: white; 
            padding: 20px; 
            text-align: center; 
        }
        .nav { 
            background: #34495e; 
            padding: 10px; 
        }
        .nav a { 
            color: white; 
            text-decoration: none; 
            margin: 0 15px; 
        }
        .content { 
            margin: 20px 0; 
        }
        .card { 
            border: 1px solid #ddd; 
            padding: 20px; 
            margin: 10px 0; 
            border-radius: 5px; 
        }
        .status { 
            background: #d4edda; 
            padding: 10px; 
            border-radius: 5px; 
        }
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
    
    return HttpResponse(HTTP_STATUS_OK, MIME_TYPE_HTML, html);
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
        body { 
            font-family: Arial, sans-serif; 
            margin: 40px; 
        }
        .form-group { 
            margin: 15px 0; 
        }
        label { 
            display: block; 
            margin-bottom: 5px; 
            font-weight: bold; 
        }
        input, textarea, select { 
            width: 100%; 
            padding: 8px; 
            border: 1px solid #ddd; 
            border-radius: 4px; 
        }
        button { 
            background: #3498db; 
            color: white; 
            padding: 10px 20px; 
            border: none; 
            border-radius: 4px; 
            cursor: pointer; 
        }
        button:hover { 
            background: #2980b9; 
        }
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
    
    return HttpResponse(HTTP_STATUS_OK, MIME_TYPE_HTML, html);
}

HttpResponse WebServer::handle_users() {
    String html = R"(
<!DOCTYPE html>
<html>
<head>
    <title>Users - Zero Trust Gateway</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h2>User Management</h2>
    <table>
        <tr>
            <th>Username</th>
            <th>Role</th>
            <th>Status</th>
            <th>Last Login</th>
            <th>Actions</th>
        </tr>
        <tr>
            <td>admin</td>
            <td>Administrator</td>
            <td>Active</td>
            <td>Never</td>
            <td><a href="/users/edit/admin">Edit</a></td>
        </tr>
    </table>
</body>
</html>
    )";
    
    return HttpResponse(HTTP_STATUS_OK, MIME_TYPE_HTML, html);
}

HttpResponse WebServer::handle_sessions() {
    String html = R"(
<!DOCTYPE html>
<html>
<head>
    <title>Sessions - Zero Trust Gateway</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .session { border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .active { background-color: #d4edda; }
        .expired { background-color: #f8d7da; }
    </style>
</head>
<body>
    <h2>Active Sessions</h2>
    <div class="session active">
        <h3>No active sessions</h3>
        <p>Currently there are no active sessions.</p>
    </div>
</body>
</html>
    )";
    
    return HttpResponse(HTTP_STATUS_OK, MIME_TYPE_HTML, html);
}

HttpResponse WebServer::handle_logs() {
    String html = R"(
<!DOCTYPE html>
<html>
<head>
    <title>Logs - Zero Trust Gateway</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .log-entry { border: 1px solid #ddd; padding: 10px; margin: 5px 0; font-family: monospace; }
        .info { background-color: #d1ecf1; }
        .error { background-color: #f8d7da; }
        .warning { background-color: #fff3cd; }
    </style>
</head>
<body>
    <h2>System Logs</h2>
    <div class="log-entry info">
        <strong>[2024-01-01 12:00:00] INFO:</strong> Web server started on port 8080
    </div>
    <div class="log-entry info">
        <strong>[2024-01-01 12:00:01] INFO:</strong> Web interface is ready
    </div>
</body>
</html>
    )";
    
    return HttpResponse(HTTP_STATUS_OK, MIME_TYPE_HTML, html);
}

HttpResponse WebServer::handle_not_found() {
    String html = R"(
<!DOCTYPE html>
<html>
<head>
    <title>404 - Not Found</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; text-align: center; }
        .error { color: #721c24; font-size: 48px; }
    </style>
</head>
<body>
    <h1 class="error">404</h1>
    <h2>Page Not Found</h2>
    <p>The requested page could not be found.</p>
    <a href="/">Return to Home</a>
</body>
</html>
    )";
    
    return HttpResponse(404, MIME_TYPE_HTML, html);
}

// Utility methods
String WebServer::get_status_json() const {
    std::ostringstream json;
    json << "{\n";
    json << "  \"status\": \"running\",\n";
    json << "  \"active_sessions\": 0,\n";
    json << "  \"uptime\": \"0h 0m 0s\",\n";
    json << "  \"memory_usage\": \"N/A\",\n";
    json << "  \"version\": \"1.0.0\"\n";
    json << "}";
    return json.str();
}

String WebServer::get_config_json() const {
    std::ostringstream json;
    json << "{\n";
    json << "  \"server_port\": " << m_port << ",\n";
    json << "  \"log_level\": \"INFO\",\n";
    json << "  \"max_sessions\": 100,\n";
    json << "  \"session_timeout\": 30\n";
    json << "}";
    return json.str();
}

HttpResponse WebServer::make_json_response(const String& json) {
    return HttpResponse(HTTP_STATUS_OK, MIME_TYPE_JSON, json);
}

HttpResponse WebServer::make_html_response(const String& html) {
    return HttpResponse(HTTP_STATUS_OK, MIME_TYPE_HTML, html);
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

// Factory function
std::unique_ptr<WebServer> create_web_server() {
    return std::make_unique<WebServer>();
}

} // namespace zerossg
