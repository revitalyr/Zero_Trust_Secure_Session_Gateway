module;
#include <boost/asio.hpp> // Include boost asio header in global module fragment
#include <boost/asio/signal_set.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <fstream>
#include <boost/asio/use_awaitable.hpp>
module zerossg.network.gateway_server;

// Project headers
import zerossg.common;
import zerossg.types;
import zerossg.tls.tls_handler;
import zerossg.logging.logger;
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
        // m_proxy_manager = std::make_unique<ProxyManager>(m_io_context, m_tls_handler->get_context());
      
      // Initialize logger (simplified for now)
        m_logger = Logger::get("GatewayServer");
        
        // Prevent io_context::run() from returning when there is no more work
        m_work_guard.emplace(m_io_context.get_executor());

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


zerossg::Result<void> GatewayServer::start() {
    if (m_running.load()) {
        return zerossg::make_result_error<void>(zerossg::ERROR_SERVER_ALREADY_RUNNING);
    }
  
    try {
        m_running.store(true);
      
        // Start I/O threads
        start_io_threads();
        register_signal_handlers();
      
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
        
        // Stop accepting new connections
        m_acceptor->cancel();

        // Allow io_context::run() to exit
        m_work_guard.reset();

        // Stop I/O context
        m_io_context.stop();
        
        // Wait for threads to finish
        if (m_signals) {
            m_signals->cancel();
        }
        stop_io_threads();
        
        m_logger->info("Server stopped");
        
        return zerossg::make_result_success();
    } catch (const std::exception& e) {
        return zerossg::make_result_error<void>(std::format("{}{}", zerossg::ERROR_SERVER_STOP_FAILED_PREFIX, e.what()));
    }
}


Result<void> GatewayServer::setup_acceptor() {
    try {
        zerossg::TcpEndpoint endpoint(
            boost::asio::ip::make_address(m_listen_address), m_listen_port);
        
        m_acceptor = std::make_unique<zerossg::TcpAcceptor>(m_io_context);
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

    m_acceptor->async_accept(
        [this](std::shared_ptr<zerossg::TcpSocket> socket, const zerossg::ErrorCode& error) {
            handle_accept(socket, error);
        }
    );
}

void GatewayServer::handle_accept(std::shared_ptr<zerossg::TcpSocket> socket, const zerossg::ErrorCode& error) {
    if (!error) {
        register_connection(socket);
        
        if (m_logger) {
            m_logger->info("New connection from " + socket->remote_endpoint().address().to_string());
        }
        
        start_accept();
    } else {
        if (m_logger) {
            m_logger->error("Accept error: " + error.message());
        }
        
        start_accept();
    }
}

void GatewayServer::register_connection(std::shared_ptr<zerossg::TcpSocket> connection) {
    m_active_connections++;
    m_total_connections++;
}

void GatewayServer::start_io_threads() {
    for (size_t i = 0; i < m_thread_count; ++i) {
        m_io_threads.emplace_back([this]() {
            m_io_context.run();
        });
    }
}

void GatewayServer::stop_io_threads() {
    m_io_context.stop();
    
    for (auto& thread : m_io_threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    
    m_io_threads.clear();
}

void GatewayServer::register_signal_handlers() {
    m_signals = std::make_unique<boost::asio::signal_set>(m_io_context, SIGINT, SIGTERM);
#ifdef SIGQUIT
    m_signals->add(SIGQUIT);
#endif

    m_signals->async_wait([this](const boost::system::error_code& error, int signal_number) {
        if (!error) {
            m_logger->info(std::format("Received signal {}. Initiating graceful shutdown.", signal_number));
            stop();
        } else {
            m_logger->error(std::format("Error waiting for signals: {}", error.message()));
        }
    });
}

} // namespace zerossg
