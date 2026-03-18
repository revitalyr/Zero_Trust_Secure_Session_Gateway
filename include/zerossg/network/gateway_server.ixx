module;

#include <memory>
#include <string>
#include <vector>
#include <optional>
#include <thread>
#include <atomic>

export module zerossg.network.gateway_server;

import zerossg.network;
// Import required modules
import zerossg.tls.tls_handler;
import zerossg.auth.authenticator;
import zerossg.rbac.authorizer;
import zerossg.session.session_manager;
import zerossg.proxy.proxy_manager;
import zerossg.security.security_manager;
import zerossg.logging.logger;
import zerossg.third_party.nlohmann_json;
import zerossg.std;

export namespace zerossg {
    
export class GatewayServer {
public:
    GatewayServer() = default;
    ~GatewayServer();

    zerossg::Result<void> initialize(const zerossg::ConfigManager& config);
    zerossg::Result<void> start();
    zerossg::Result<void> stop();
    
    bool is_running() const { return m_running; }
    
    size_t get_active_connection_count() const { return m_active_connections.load(); }
    size_t get_total_connection_count() const { return m_total_connections.load(); }

private:
    zerossg::Result<void> setup_acceptor();
    void start_accept();
    void handle_accept(std::shared_ptr<zerossg::TcpSocket> socket, const zerossg::ErrorCode& error);
    void start_io_threads();
    void stop_io_threads();
    void register_connection(std::shared_ptr<zerossg::TcpSocket> connection);

    zerossg::String m_listen_address{"127.0.0.1"};
    uint16_t m_listen_port{8080};
    std::unique_ptr<zerossg::TcpAcceptor> m_acceptor;
    zerossg::IoContext m_io_context;
    std::optional<zerossg::ExecutorWorkGuard> m_work_guard;
    std::vector<std::thread> m_io_threads;
    std::atomic<bool> m_running{false};
    size_t m_thread_count{4};
    std::unique_ptr<zerossg::TlsHandler> m_tls_handler;
    std::unique_ptr<zerossg::AuthenticationManager> m_auth_manager;
    std::unique_ptr<zerossg::AuthorizationManager> m_authz_manager;
    std::unique_ptr<zerossg::SessionManager> m_session_manager;
    std::unique_ptr<zerossg::SecurityManager> m_security_manager;
    zerossg::String m_tls_cert_file{"server.crt"};
    zerossg::String m_tls_key_file{"server.key"};
    std::atomic<size_t> m_active_connections{0};
    std::atomic<size_t> m_total_connections{0};
    std::unique_ptr<zerossg::ProxyManager> m_proxy_manager;
    std::shared_ptr<zerossg::Logger> m_logger;
    std::unique_ptr<zerossg::SignalSet> m_signals;
};

}
