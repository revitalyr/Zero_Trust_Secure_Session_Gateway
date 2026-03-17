module;

#include <mutex>
#include <unordered_map>
#include <atomic>
#include <vector>
#include <string>
#include <memory>

export module zerossg.proxy.proxy_manager;

import zerossg.interfaces;
export import zerossg.common;
import zerossg.network;
export import zerossg.types;

export namespace zerossg {

// Forward declarations
export class ProxyManager;
export class ProxyConnection;

// ProxyConnection class
export class ProxyConnection : public std::enable_shared_from_this<ProxyConnection> {
public:
    ProxyConnection(ProxyManager& manager, const std::string& session_id,
                   const ConnectionInfo& client_conn, const TargetService& target,
                   SslContext& client_ssl_context, SslContext& target_ssl_context);
    ~ProxyConnection();

    void start();
    void stop();
    bool is_active() const { return m_active.load(); }

    // Accessors for sockets (used by manager or internal logic)
    TcpSocket& get_client_socket();
    TcpSocket& get_target_socket();

private:
    void setup_ssl_if_needed();
    void connect_to_target();
    void handle_target_connect(const ErrorCode& error);
    void start_data_forwarding();

    void read_from_client();
    void handle_client_read(const ErrorCode& error, size_t bytes_transferred);
    void write_to_target(size_t bytes_to_write);
    void handle_target_write(const ErrorCode& error, size_t bytes_transferred);

    void read_from_target();
    void handle_target_read(const ErrorCode& error, size_t bytes_transferred);
    void write_to_client(size_t bytes_to_write);
    void handle_client_write(const ErrorCode& error, size_t bytes_transferred);

    void handle_error(const std::string& operation, const ErrorCode& error);
    void cleanup();

    ProxyManager& m_manager;
    std::string m_session_id;
    ConnectionInfo m_client_conn;
    TargetService m_target_service;

    TcpSocket m_client_socket;
    TcpSocket m_target_socket;

    // Using pointer for optional SSL streams
    std::unique_ptr<SslStream> m_client_ssl_socket;
    std::unique_ptr<SslStream> m_target_ssl_socket;

    std::atomic<bool> m_active{false};
    uint64_t m_bytes_sent{0};
    uint64_t m_bytes_received{0};

    StreamBuffer m_client_to_target_buffer;
    StreamBuffer m_target_to_client_buffer;
};

// ProxyManager concrete class
export class ProxyManager : public IProxy {
public:
    ProxyManager(IoContext& io_context, SslContext& ssl_context);
    ~ProxyManager();

    Result<void> start_proxy(const SessionId& session_id, const ConnectionInfo& client_conn, 
                           const TargetService& target) override;
    Result<void> stop_proxy(const SessionId& session_id) override;
    bool is_proxy_active(const SessionId& session_id) override;

    // Additional methods specific to ProxyManager
    Result<std::vector<std::string>> get_active_proxies();
    Result<void> cleanup_inactive_proxies();
    size_t get_active_proxy_count() const;
    uint64_t get_total_bytes_transferred() const;
    
    // Internal methods for ProxyConnection
    void remove_proxy(const std::string& session_id);
    void update_statistics(uint64_t bytes_transferred);

    // Friend declaration to allow ProxyConnection to access internals if needed
    friend class ProxyConnection;

private:
    IoContext& m_io_context;
    SslContext& m_ssl_context;

    std::unordered_map<std::string, std::shared_ptr<ProxyConnection>> m_proxies;
    mutable std::mutex m_proxies_mutex;

    std::atomic<uint64_t> m_total_bytes_transferred{0};
};

} // namespace zerossg
