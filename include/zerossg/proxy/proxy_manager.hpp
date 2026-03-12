#pragma once

// Project headers
#include "zerossg/interfaces.hpp"
#include "zerossg/types.hpp"

// C++ Standard Library headers
#include <atomic>
#include <memory>
#include <thread>
#include <unordered_map>

namespace zerossg {

class ProxyConnection;
using ProxyConnectionPtr = std::shared_ptr<ProxyConnection>;

class ProxyManager : public IProxy {
public:
    ProxyManager(boost::asio::io_context& io_context);
    ~ProxyManager() override;
    
    // IProxy interface
    Result<void> start_proxy(const string& session_id, const ConnectionInfo& client_conn, 
                           const TargetService& target) override;
    Result<void> stop_proxy(const string& session_id) override;
    bool is_proxy_active(const string& session_id) override;
    
    // Proxy management
    Result<vector<string>> get_active_proxies();
    Result<void> cleanup_inactive_proxies();
    
    // Statistics
    size_t get_active_proxy_count() const;
    uint64_t get_total_bytes_transferred() const;
    
private:
    // Proxy storage
    unordered_map<string, ProxyConnectionPtr> m_proxies;
    mutable std::mutex m_proxies_mutex;
    
    // I/O context
    boost::asio::io_context& m_io_context;
    
    // Statistics
    std::atomic<uint64_t> m_total_bytes_transferred{0};
    
    // Helper methods
    void remove_proxy(const string& session_id);
    void update_statistics(uint64_t bytes_transferred);
    
    friend class ProxyConnection;
};

// Individual proxy connection between client and target service
class ProxyConnection : public std::enable_shared_from_this<ProxyConnection> {
public:
    ProxyConnection(ProxyManager& manager, const string& session_id,
                   const ConnectionInfo& client_conn, const TargetService& target);
    ~ProxyConnection();
    
    void start();
    void stop();
    
    bool is_active() const { return m_active; }
    const string& get_session_id() const { return m_session_id; }
    
private:
    ProxyManager& m_manager;
    string m_session_id;
    ConnectionInfo m_client_conn;
    TargetService m_target_service;
    std::atomic<bool> m_active{false};
    
    // Network sockets
    boost::asio::ip::tcp::socket m_client_socket;
    boost::asio::ip::tcp::socket m_target_socket;
    
    // SSL sockets for TLS connections
    std::unique_ptr<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>> m_client_ssl_socket;
    std::unique_ptr<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>> m_target_ssl_socket;
    
    // Buffers for data transfer
    boost::asio::streambuf m_client_to_target_buffer;
    boost::asio::streambuf m_target_to_client_buffer;
    
    // Statistics
    uint64_t m_bytes_sent{0};
    uint64_t m_bytes_received{0};
    
    // Connection lifecycle
    void connect_to_target();
    void handle_target_connect(const boost::system::error_code& error);
    void start_data_forwarding();
    
    // Data forwarding
    void read_from_client();
    void handle_client_read(const boost::system::error_code& error, size_t bytes_transferred);
    void write_to_target(size_t bytes_to_write);
    void handle_target_write(const boost::system::error_code& error, size_t bytes_transferred);
    
    void read_from_target();
    void handle_target_read(const boost::system::error_code& error, size_t bytes_transferred);
    void write_to_client(size_t bytes_to_write);
    void handle_client_write(const boost::system::error_code& error, size_t bytes_transferred);
    
    // Error handling
    void handle_error(const string& operation, const boost::system::error_code& error);
    void cleanup();
    
    // Helper methods
    boost::asio::ip::tcp::socket& get_client_socket();
    boost::asio::ip::tcp::socket& get_target_socket();
    void setup_ssl_if_needed();
};

} // namespace zerossg
