module;

#include <memory>
#include <string>
#include <vector>
#include <optional>
#include <thread>
#include <atomic>

export module zerossg.network.gateway_server;

import zerossg.network;
import zerossg.std;
import zerossg.common;

export namespace zerossg {

// Forward declarations to reduce module interface complexity
class TlsHandler;
class AuthenticationManager;
class AuthorizationManager;
class SessionManager;
class SecurityManager;
class ProxyManager;
class Logger;
class ConfigManager;
    
export class GatewayServer {
public:
    GatewayServer() = default;
    ~GatewayServer();

    Result<void> initialize(const ConfigManager& config);
    Result<void> start();
    Result<void> stop();
    
    bool is_running() const { return m_running; }
    
    size_t get_active_connection_count() const { return m_active_connections.load(); }
    size_t get_total_connection_count() const { return m_total_connections.load(); }

private:
    Result<void> setup_acceptor();
    void start_accept();
    void handle_accept(std::shared_ptr<TcpSocket> socket, const ErrorCode& error);
    void start_io_threads();
    void stop_io_threads();
    void register_connection(std::shared_ptr<TcpSocket> connection);
    void register_signal_handlers();

    String m_listen_address{"127.0.0.1"};
    uint16_t m_listen_port{8080};
    std::unique_ptr<TcpAcceptor> m_acceptor;
    IoContext m_io_context;
    std::optional<ExecutorWorkGuard> m_work_guard;
    std::vector<std::thread> m_io_threads;
    std::atomic<bool> m_running{false};
    size_t m_thread_count{4};
    std::unique_ptr<TlsHandler> m_tls_handler;
    std::unique_ptr<AuthenticationManager> m_auth_manager;
    std::unique_ptr<AuthorizationManager> m_authz_manager;
    std::unique_ptr<SessionManager> m_session_manager;
    std::unique_ptr<SecurityManager> m_security_manager;
    String m_tls_cert_file{"server.crt"};
    String m_tls_key_file{"server.key"};
    std::atomic<size_t> m_active_connections{0};
    std::atomic<size_t> m_total_connections{0};
    std::unique_ptr<ProxyManager> m_proxy_manager;
    std::shared_ptr<Logger> m_logger;
    std::unique_ptr<SignalSet> m_signals;
};

}
