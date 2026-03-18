export module zerossg.network.gateway_server;

import zerossg.common;
import zerossg.types;

// Forward declarations for manager classes to avoid including full headers
export namespace zerossg {
    class AuthenticationManager;
    class AuthorizationManager;
    class SessionManager;
    class SecurityManager;
    class TlsHandler;
    class Logger;
    class Connection;
    using ConnectionPtr = SharedPtr<Connection>;
}

export namespace zerossg {

export class GatewayServer {
public:
    GatewayServer();
    ~GatewayServer();

    Result<void> initialize(const ConfigFileName& config_file);
    Result<void> start();
    Result<void> stop();
    
    bool is_running() const { return m_running.load(); }
    Count get_active_connections() const { return m_active_connections.load(); }
    Count get_total_connections() const { return m_total_connections.load(); }

    // Public members for Connection to access
    UniquePtr<AuthenticationManager> m_auth_manager;
    UniquePtr<AuthorizationManager> m_authz_manager;
    UniquePtr<SessionManager> m_session_manager;
    UniquePtr<SecurityManager> m_security_manager;
    SharedPtr<Logger> m_logger;

    void unregister_connection(const ConnectionPtr& connection);

private:
    void start_accept();
    void handle_accept(const ConnectionPtr& connection, const boost::system::error_code& error);
    void start_io_threads();
    void stop_io_threads();
    void register_connection(const ConnectionPtr& connection);
    Result<void> setup_acceptor();

    IoContext m_io_context;
    UniquePtr<TcpAcceptor> m_acceptor;
    UniquePtr<TlsHandler> m_tls_handler;
    
    std::atomic<bool> m_running{false};
    std::atomic<Count> m_active_connections{0};
    std::atomic<Count> m_total_connections{0};
    
    Vector<std::thread> m_io_threads;
    Count m_thread_count{std::thread::hardware_concurrency()};

    // Config values
    IpAddress m_listen_address;
    PortNo m_listen_port;
    FilePath m_tls_cert_file;
    FilePath m_tls_key_file;
};

} // namespace zerossg