#pragma once

// Project headers
#include "zerossg/interfaces.hpp"
#include "zerossg/tls/tls_handler.hpp"
#include "zerossg/auth/authenticator.hpp"
#include "zerossg/rbac/authorizer.hpp"
#include "zerossg/session/session_manager.hpp"
#include "zerossg/security/security_manager.hpp"
#include "zerossg/logging/logger.hpp"

// C++ Standard Library headers
#include <atomic>
#include <memory>
#include <thread>

namespace zerossg {

class Connection;
using ConnectionPtr = std::shared_ptr<Connection>;

class GatewayServer {
public:
    GatewayServer();
    ~GatewayServer();
    
    // Server lifecycle
    Result<void> initialize(const string& config_file);
    Result<void> start();
    Result<void> stop();
    bool is_running() const { return m_running.load(); }
    
    // Configuration
    void set_listen_port(uint16_t port) { m_listen_port = port; }
    void set_listen_address(const string& address) { m_listen_address = address; }
    void set_tls_cert_file(const string& cert_file) { m_tls_cert_file = cert_file; }
    void set_tls_key_file(const string& key_file) { m_tls_key_file = key_file; }
    
    // Statistics
    size_t get_active_connections() const { return m_active_connections.load(); }
    size_t get_total_connections() const { return m_total_connections.load(); }
    
private:
    // Network components
    boost::asio::io_context m_io_context;
    std::unique_ptr<boost::asio::ssl::context> m_ssl_context;
    std::unique_ptr<TlsHandler> m_tls_handler;
    std::unique_ptr<boost::asio::ip::tcp::acceptor> m_acceptor;
    
    // Business logic components
    std::unique_ptr<AuthenticationManager> m_auth_manager;
    std::unique_ptr<AuthorizationManager> m_authz_manager;
    std::unique_ptr<SessionManager> m_session_manager;
    std::unique_ptr<SecurityManager> m_security_manager;
    std::shared_ptr<ILogger> m_logger;
    
    // Threading
    std::vector<std::thread> m_io_threads;
    std::atomic<bool> m_running{false};
    std::atomic<size_t> m_active_connections{0};
    std::atomic<size_t> m_total_connections{0};
    
    // Configuration
    string m_listen_address{"0.0.0.0"};
    uint16_t m_listen_port{8443};
    string m_tls_cert_file{"server.crt"};
    string m_tls_key_file{"server.key"};
    size_t m_thread_count{std::thread::hardware_concurrency()};
    
    // Server operations
    Result<void> setup_tls();
    Result<void> setup_acceptor();
    void start_accept();
    void handle_accept(ConnectionPtr connection, const boost::system::error_code& error);
    
    // Threading
    void start_io_threads();
    void stop_io_threads();
    
    // Connection management
    void register_connection(ConnectionPtr connection);
    void unregister_connection(ConnectionPtr connection);
    
    friend class Connection;
};

// Connection class represents a single client connection
class Connection : public std::enable_shared_from_this<Connection> {
public:
    Connection(GatewayServer& server, boost::asio::io_context& io_context, 
               boost::asio::ssl::context& ssl_context);
    ~Connection();
    
    void start();
    void stop();
    
    const string& get_client_ip() const { return m_client_ip; }
    const string& get_session_id() const { return m_session_id; }
    bool is_authenticated() const { return m_authenticated; }
    
private:
    GatewayServer& m_server;
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> m_socket;
    boost::asio::streambuf m_buffer;
    
    // Connection state
    string m_client_ip;
    string m_session_id;
    bool m_authenticated{false};
    User m_user;
    
    // Async operations
    void do_handshake();
    void do_read();
    void handle_read(const boost::system::error_code& error, size_t bytes_transferred);
    void do_write(const string& response);
    void handle_write(const boost::system::error_code& error);
    
    // Protocol handling
    void handle_request(const string& request);
    string process_login_request(const string& request);
    string process_session_request(const string& request);
    string process_proxy_request(const string& request);
    string process_logout_request(const string& request);
    
    // Helper methods
    string create_response(const string& status, const string& message, const nlohmann::json& data = nlohmann::json{});
    string create_error_response(const string& error);
    void log_connection_event(const string& event_type, const string& details);
};

} // namespace zerossg
