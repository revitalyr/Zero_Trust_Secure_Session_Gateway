module;
#include <boost/asio.hpp> // Include boost asio header in global module fragment
#include <boost/asio/ssl.hpp>
module zerossg.network.gateway_server;

// Project headers
import zerossg.common;
import zerossg.types;
import zerossg.tls.tls_handler;
import zerossg.rbac.authorizer;
import zerossg.session.session_manager;
import zerossg.proxy.proxy_manager;
import zerossg.security.security_manager;
import zerossg.logging.logger;

// Standard library imports
import zerossg.std;

// Import new connection module
import zerossg.network.connection;
import zerossg.auth.authenticator;
import zerossg.config.config_manager;

namespace zerossg {

// GatewayServer implementation
GatewayServer::GatewayServer() = default;

GatewayServer::~GatewayServer() {
    stop();
}

Result<void> GatewayServer::initialize(const zerossg::ConfigManager& config) {
    try {
        // Load configuration from ConfigManager
        m_listen_address = config.get_string("server.listen_address", "127.0.0.1");
        m_listen_port = static_cast<uint16_t>(config.get_int("server.listen_port", 8080));
        m_tls_cert_file = config.get_string("server.tls_cert_file", "server.crt");
        m_tls_key_file = config.get_string("server.tls_key_file", "server.key");
        m_thread_count = static_cast<size_t>(config.get_int("server.thread_count", 4));

        // Initialize TLS handler
        m_tls_handler = std::make_unique<TlsHandler>(m_io_context);
        auto tls_result = m_tls_handler->initialize(m_tls_cert_file, m_tls_key_file);
        if (!tls_result.has_value()) {
            return zerossg::make_result_error(std::format("{}{}", zerossg::ERROR_TLS_INIT_FAILED_PREFIX, tls_result.error()));
        }
        
        // Initialize business logic components
        m_auth_manager = std::make_unique<AuthenticationManager>();
        m_authz_manager = std::make_unique<AuthorizationManager>();
        m_session_manager = std::make_unique<SessionManager>();
        m_security_manager = std::make_unique<SecurityManager>();
        
        // Initialize logger (simplified for now)
        m_logger = Logger::get("GatewayServer");
        
        // Setup networking
        auto setup_result = setup_acceptor();
        if (!setup_result.has_value()) {
            return setup_result;
        }
        
        return zerossg::make_result_success();
    } catch (const std::exception& e) {
        return zerossg::make_result_error(std::format("{}{}", zerossg::ERROR_SERVER_INIT_FAILED_PREFIX, e.what()));
    }
}

Result<void> GatewayServer::start() {
    if (m_running.load()) {
        return zerossg::make_result_error<void>(zerossg::ERROR_SERVER_ALREADY_RUNNING);
    }
    
    try {
        m_running.store(true);
        
        // Start I/O threads
        start_io_threads();
        
        // Start accepting connections
        start_accept();
        
        m_logger->info(std::format("Server started on {}:{}", m_listen_address, m_listen_port));
        
        return zerossg::make_result_success();
    } catch (const std::exception& e) {
        m_running.store(false);
        return zerossg::make_result_error<void>(std::format("{}{}", zerossg::ERROR_SERVER_START_FAILED_PREFIX, e.what()));
    }
}

Result<void> GatewayServer::stop() {
    if (!m_running.load()) {
        return zerossg::make_result_success();
    }
    
    m_running.store(false);
    
    try {
        // Close acceptor
        if (m_acceptor) {
            m_acceptor->close();
        }
        
        // Stop I/O context
        m_io_context.stop();
        
        // Wait for threads to finish
        stop_io_threads();
        
        m_logger->info("Server stopped");
        
        return zerossg::make_result_success();
    } catch (const std::exception& e) {
        return zerossg::make_result_error<void>(std::format("{}{}", zerossg::ERROR_SERVER_STOP_FAILED_PREFIX, e.what()));
    }
}

Result<void> GatewayServer::setup_acceptor() {
    try {
        boost::asio::ip::tcp::endpoint endpoint(
            boost::asio::ip::make_address(m_listen_address), m_listen_port);
        
        m_acceptor = std::make_unique<boost::asio::ip::tcp::acceptor>(m_io_context);
        m_acceptor->open(endpoint.protocol());
        m_acceptor->set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
        m_acceptor->bind(endpoint);
        m_acceptor->listen(boost::asio::socket_base::max_listen_connections);
        
        return zerossg::make_result_success();
    } catch (const std::exception& e) {
        return zerossg::make_result_error<void>(std::format("{}{}", zerossg::ERROR_ACCEPTOR_SETUP_FAILED_PREFIX, e.what()));
    }
}

void GatewayServer::start_accept() {
    if (!m_running.load()) {
        return;
    }
    auto connection = std::make_shared<Connection>(*this, m_io_context, m_tls_handler->get_context());
    
    m_acceptor->async_accept(
        connection->m_socket.lowest_layer(),
        [this, connection](const boost::system::error_code& error) {
            handle_accept(connection, error);
        }
    );
}

void GatewayServer::handle_accept(const ConnectionPtr& connection, const boost::system::error_code& error) {
    if (!error) {
        register_connection(connection);
        connection->start();
    } else {
        m_logger->error(std::format("Accept error: {}", error.message()));
    }
    
    // Continue accepting new connections
    start_accept();
}

void GatewayServer::start_io_threads() {
    for (size_t i = 0; i < m_thread_count; ++i) {
        m_io_threads.emplace_back([this]() {
            while (m_running.load()) {
                try {
                    m_io_context.run_for(std::chrono::milliseconds(100));
                } catch (const std::exception& e) {
                    m_logger->error(std::format("I/O thread error: {}", e.what()));
                }
            }
        });
    }
}

void GatewayServer::stop_io_threads() {
    for (auto& thread : m_io_threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    m_io_threads.clear();
}

void GatewayServer::register_connection(const ConnectionPtr& connection) {
    m_active_connections.fetch_add(1);
    m_total_connections.fetch_add(1);
}

void GatewayServer::unregister_connection(const ConnectionPtr& connection) {
    m_active_connections.fetch_sub(1);
}

} // namespace zerossg
