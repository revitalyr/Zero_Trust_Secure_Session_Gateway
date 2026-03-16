module;

export module zerossg.network.gateway_server;

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

// Forward declarations
export class zerossg::GatewayServer;
export class zerossg::Connection;
export class zerossg::ConfigManager;

// Export GatewayServer class
export class zerossg::GatewayServer {
public:
    GatewayServer() = default;
    ~GatewayServer();

    zerossg::Result<void> initialize(const zerossg::ConfigManager& config);
    zerossg::Result<void> start();
    zerossg::Result<void> stop();

private:
    zerossg::Result<void> setup_acceptor();
    void start_accept();
    void handle_accept(std::shared_ptr<zerossg::Connection> connection, const boost::system::error_code& error);
    void start_io_threads();
    void stop_io_threads();
    void register_connection(std::shared_ptr<zerossg::Connection> connection);

    zerossg::String m_listen_address{"127.0.0.1"};
    uint16_t m_listen_port{8080};
    std::unique_ptr<boost::asio::ip::tcp::acceptor> m_acceptor;
    zerossg::IoContext m_io_context;
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
};
