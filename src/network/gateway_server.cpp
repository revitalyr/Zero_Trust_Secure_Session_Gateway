// Project headers
import zerossg.common;
import zerossg.types;
import zerossg.network.gateway_server;
import zerossg.tls.tls_handler;
import zerossg.result;
import zerossg.auth.authenticator;
import zerossg.rbac.authorizer;
import zerossg.session.session_manager;
import zerossg.proxy.proxy_manager;
import zerossg.security.security_manager;
import zerossg.logging.logger;

// Standard library imports
import zerossg.third_party.nlohmann_json;
import zerossg.std;

using json = nlohmann::json;

namespace zerossg {

// GatewayServer implementation
GatewayServer::GatewayServer() = default;

GatewayServer::~GatewayServer() {
    stop();
}

Result<void> GatewayServer::initialize(const zerossg::ConfigFileName& config_file) {
    try {
        // Initialize TLS handler
        m_tls_handler = zerossg::make_unique<TlsHandler>(m_io_context);
        auto tls_result = m_tls_handler->initialize(m_tls_cert_file, m_tls_key_file);
        if (!tls_result.is_success()) {
            return zerossg::Result<void>::error("TLS initialization failed: " + tls_result.error());
        }
        
        // Initialize business logic components
        m_auth_manager = zerossg::make_unique<AuthenticationManager>();
        m_authz_manager = zerossg::make_unique<AuthorizationManager>();
        m_session_manager = zerossg::make_unique<SessionManager>();
        m_security_manager = zerossg::make_unique<SecurityManager>();
        
        // Initialize logger (simplified for now)
        // m_logger = std::make_shared<Logger>();
        
        // Setup networking
        auto setup_result = setup_acceptor();
        if (!setup_result.is_success()) {
            return setup_result;
        }
        
        return zerossg::Result<void>::success();
    } catch (const std::exception& e) {
        return zerossg::Result<void>::error("Server initialization failed: " + zerossg::String(e.what()));
    }
}

Result<void> GatewayServer::start() {
    if (m_running.load()) {
        return zerossg::Result<void>::error("Server is already running");
    }
    
    try {
        m_running.store(true);
        
        // Start I/O threads
        start_io_threads();
        
        // Start accepting connections
        start_accept();
        
        zerossg::cout << "Zero Trust Secure Session Gateway started on " 
                  << m_listen_address << ":" << m_listen_port << zerossg::endl;
        
        return zerossg::Result<void>::success();
    } catch (const std::exception& e) {
        m_running.store(false);
        return zerossg::Result<void>::error("Failed to start server: " + zerossg::String(e.what()));
    }
}

Result<void> GatewayServer::stop() {
    if (!m_running.load()) {
        return Result<void>::success();
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
        
        zerossg::cout << "Zero Trust Secure Session Gateway stopped" << zerossg::endl;
        
        return zerossg::Result<void>::success();
    } catch (const std::exception& e) {
        return zerossg::Result<void>::error("Error stopping server: " + zerossg::String(e.what()));
    }
}

Result<void> GatewayServer::setup_acceptor() {
    try {
        boost::asio::ip::tcp::endpoint endpoint(
            boost::asio::ip::make_address(m_listen_address), m_listen_port);
        
        m_acceptor = zerossg::make_unique<boost::asio::ip::tcp::acceptor>(m_io_context);
        m_acceptor->open(endpoint.protocol());
        m_acceptor->set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
        m_acceptor->bind(endpoint);
        m_acceptor->listen(boost::asio::socket_base::max_listen_connections);
        
        return zerossg::Result<void>::success();
    } catch (const std::exception& e) {
        return zerossg::Result<void>::error("Failed to setup acceptor: " + zerossg::String(e.what()));
    }
}

void GatewayServer::start_accept() {
    if (!m_running.load()) {
        return;
    }
    
    auto connection = zerossg::make_shared<Connection>(*this, m_io_context, m_tls_handler->get_context());
    
    m_acceptor->async_accept(
        connection->m_socket.lowest_layer(),
        [this, connection](const boost::system::error_code& error) {
            handle_accept(connection, error);
        }
    );
}

void GatewayServer::handle_accept(ConnectionPtr connection, const boost::system::error_code& error) {
    if (!error) {
        register_connection(connection);
        connection->start();
    } else {
        zerossg::cerr << "Accept error: " << error.message() << zerossg::endl;
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
                    zerossg::cerr << "I/O thread error: " << e.what() << zerossg::endl;
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

void GatewayServer::register_connection(ConnectionPtr connection) {
    m_active_connections.fetch_add(1);
    m_total_connections.fetch_add(1);
}

void GatewayServer::unregister_connection(ConnectionPtr connection) {
    m_active_connections.fetch_sub(1);
}

// Connection implementation
Connection::Connection(GatewayServer& server, boost::asio::io_context& io_context, 
                       boost::asio::ssl::context& ssl_context)
    : m_server(server)
    , m_socket(io_context, ssl_context) {
}

Connection::~Connection() {
    stop();
}

void Connection::start() {
    m_client_ip = m_socket.lowest_layer().remote_endpoint().address().to_string();
    do_handshake();
}

void Connection::stop() {
    try {
        if (m_socket.lowest_layer().is_open()) {
            m_socket.lowest_layer().close();
        }
    } catch (...) {
        // Ignore errors during shutdown
    }
}

void Connection::do_handshake() {
    m_socket.async_handshake(
        boost::asio::ssl::stream_base::server,
        [self = shared_from_this()](const boost::system::error_code& error) {
            if (!error) {
                self->do_read();
            } else {
                zerossg::cerr << "Handshake error: " << error.message() << zerossg::endl;
            }
        }
    );
}

void Connection::do_read() {
    boost::asio::async_read_until(
        m_socket, m_buffer, "\n\n",
        [self = shared_from_this()](const boost::system::error_code& error, size_t bytes_transferred) {
            self->handle_read(error, bytes_transferred);
        }
    );
}

void Connection::handle_read(const boost::system::error_code& error, size_t bytes_transferred) {
    if (error) {
        if (error != boost::asio::error::eof) {
            zerossg::cerr << "Read error: " << error.message() << zerossg::endl;
        }
        return;
    }
    
    // Read the request
    zerossg::istream is(&m_buffer);
    zerossg::String request_line;
    zerossg::getline(is, request_line);
    
    // Process the request
    handle_request(request_line);
    
    // Continue reading
    do_read();
}

void Connection::handle_request(const zerossg::RequestString& request) {
    try {
        json request_json = json::parse(request);
        zerossg::String request_type = request_json.value("type", "");
        
        zerossg::String response;
        
        if (request_type == "login") {
            response = process_login_request(request);
        } else if (request_type == "session") {
            response = process_session_request(request);
        } else if (request_type == "proxy") {
            response = process_proxy_request(request);
        } else if (request_type == "logout") {
            response = process_logout_request(request);
        } else {
            response = create_error_response("Unknown request type: " + zerossg::String(request_type));
        }
        
        do_write(response + "\n\n");
    } catch (const json::exception& e) {
        do_write(create_error_response("Invalid JSON: " + zerossg::String(e.what())) + "\n\n");
    } catch (const std::exception& e) {
        do_write(create_error_response("Request processing error: " + zerossg::String(e.what())) + "\n\n");
    }
}

zerossg::ResponseString Connection::process_login_request(const zerossg::RequestString& request) {
    json request_json = json::parse(request);
    zerossg::String username = request_json.value("username", "");
    zerossg::String password = request_json.value("password", "");
    
    if (username.empty() || password.empty()) {
        return create_error_response("Username and password required");
    }
    
    // Check rate limiting
    auto rate_limit_result = m_server.m_security_manager->check_rate_limit(m_client_ip);
    if (!rate_limit_result.is_success() || !rate_limit_result.value()) {
        return create_error_response("Rate limit exceeded");
    }
    
    // Authenticate
    auto auth_result = m_server.m_auth_manager->authenticate(username, password);
    if (!auth_result.is_success()) {
        m_server.m_security_manager->record_failed_attempt(m_client_ip);
        return create_error_response("Authentication failed: " + auth_result.error());
    }
    
    m_server.m_security_manager->record_successful_login(m_client_ip);
    
    // Create user object
    auto user_result = m_server.m_auth_manager->get_user(username);
    if (!user_result.is_success() || !user_result.value().has_value()) {
        return create_error_response("User not found after authentication");
    }
    
    m_user = user_result.value().value();
    m_authenticated = true;
    
    zerossg::String token = auth_result.value();
    
    json response_data = {
        {"token", token},
        {"user", {
            {"username", m_user.username},
            {"role", role_to_string(m_user.role)}
        }}
    };
    
    return create_response("success", "Login successful", response_data);
}

zerossg::ResponseString Connection::process_session_request(const zerossg::RequestString& request) {
    if (!m_authenticated) {
        return create_error_response("Not authenticated");
    }
    
    json request_json = json::parse(request);
    zerossg::String target_service = request_json.value("target_service", "");
    
    if (target_service.empty()) {
        return create_error_response("Target service required");
    }
    
    // Check authorization
    auto authz_result = m_server.m_authz_manager->can_access_service(m_user, target_service);
    if (!authz_result.is_success() || !authz_result.value()) {
        return create_error_response("Access denied to service: " + target_service);
    }
    
    // Create session
    auto session_result = m_server.m_session_manager->create_session(m_user, m_client_ip, target_service);
    if (!session_result.is_success()) {
        return create_error_response("Session creation failed: " + session_result.error());
    }
    
    m_session_id = session_result.value();
    
    json response_data = {
        {"session_id", m_session_id},
        {"target_service", target_service}
    };
    
    return create_response("success", "Session created", response_data);
}

zerossg::ResponseString Connection::process_proxy_request(const zerossg::RequestString& request) {
    if (!m_authenticated || m_session_id.empty()) {
        return create_error_response("No active session");
    }
    
    // This is a simplified proxy implementation
    // In a real implementation, you would handle the actual data forwarding
    json response_data = {
        {"session_id", m_session_id},
        {"status", "proxy_active"}
    };
    
    return create_response("success", "Proxy request processed", response_data);
}

zerossg::ResponseString Connection::process_logout_request(const zerossg::RequestString& request) {
    if (!m_authenticated) {
        return create_error_response("Not authenticated");
    }
    
    // Terminate session if active
    if (!m_session_id.empty()) {
        m_server.m_session_manager->terminate_session(m_session_id);
        m_session_id.clear();
    }
    
    m_authenticated = false;
    
    return create_response("success", "Logout successful");
}

void Connection::do_write(const zerossg::ResponseString& response) {
    boost::asio::async_write(
        m_socket, boost::asio::buffer(response),
        [self = shared_from_this()](const boost::system::error_code& error, size_t) {
            if (error) {
                zerossg::cerr << "Write error: " << error.message() << zerossg::endl;
            }
        }
    );
}

zerossg::ResponseString Connection::create_response(const zerossg::StatusString& status, const zerossg::MessageString& message, const json& data) {
    json response = {
        {"status", status},
        {"message", message},
        {"timestamp", zerossg::chrono::duration_cast<zerossg::chrono::seconds>(
            zerossg::chrono::system_clock::now().time_since_epoch()).count()}
    };
    
    if (!data.empty()) {
        response["data"] = data;
    }
    
    return response.dump();
}

zerossg::ResponseString Connection::create_error_response(const zerossg::ErrorString& error) {
    return create_response("error", error);
}

void Connection::log_connection_event(const zerossg::EventTypeString& event_type, const zerossg::LogDetails& details) {
    // Simplified logging - in production, use the actual logger
    zerossg::cout << "[" << event_type << "] " << m_client_ip << ": " << details << zerossg::endl;
}

} // namespace zerossg
