module zerossg.network.gateway_server;

// Project headers
import zerossg.common;
import zerossg.types;
import zerossg.tls.tls_handler;
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
            return zerossg::make_result_error(std::format("{}{}", zerossg::ERROR_TLS_INIT_FAILED_PREFIX, tls_result.error()));
        }
        
        // Initialize business logic components
        m_auth_manager = zerossg::make_unique<AuthenticationManager>();
        m_authz_manager = zerossg::make_unique<AuthorizationManager>();
        m_session_manager = zerossg::make_unique<SessionManager>();
        m_security_manager = zerossg::make_unique<SecurityManager>();
        
        // Initialize logger (simplified for now)
        m_logger = Logger::get("GatewayServer");
        
        // Setup networking
        auto setup_result = setup_acceptor();
        if (!setup_result.is_success()) {
            return setup_result;
        }
        
        return zerossg::make_result_success();
    } catch (const std::exception& e) {
        return zerossg::make_result_error(std::format("{}{}", zerossg::ERROR_SERVER_INIT_FAILED_PREFIX, e.what()));
    }
}

Result<void> GatewayServer::start() {
    if (m_running.load()) {
        return zerossg::make_result_error(zerossg::ERROR_SERVER_ALREADY_RUNNING);
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
        return zerossg::make_result_error(std::format("{}{}", zerossg::ERROR_SERVER_START_FAILED_PREFIX, e.what()));
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
        return zerossg::make_result_error(std::format("{}{}", zerossg::ERROR_SERVER_STOP_FAILED_PREFIX, e.what()));
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
        
        return zerossg::make_result_success();
    } catch (const std::exception& e) {
        return zerossg::make_result_error(std::format("{}{}", zerossg::ERROR_ACCEPTOR_SETUP_FAILED_PREFIX, e.what()));
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
                self->m_server.m_logger->error(std::format("Handshake error: {}", error.message()));
            }
        }
    );
}

void Connection::do_read() {
    boost::asio::async_read_until(
        m_socket, m_buffer, zerossg::MESSAGE_DELIMITER,
        [self = shared_from_this()](const boost::system::error_code& error, size_t bytes_transferred) {
            self->handle_read(error, bytes_transferred);
        }
    );
}

void Connection::handle_read(const boost::system::error_code& error, size_t bytes_transferred) {
    if (error) {
        if (error != boost::asio::error::eof) {
            m_server.m_logger->error(std::format("Read error: {}", error.message()));
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
        zerossg::String request_type = request_json.value(zerossg::JSON_KEY_TYPE, "");
        
        zerossg::String response;
        
        if (request_type == zerossg::JSON_VALUE_LOGIN) {
            response = process_login_request(request);
        } else if (request_type == zerossg::JSON_VALUE_SESSION) {
            response = process_session_request(request);
        } else if (request_type == zerossg::JSON_VALUE_PROXY) {
            response = process_proxy_request(request);
        } else if (request_type == zerossg::JSON_VALUE_LOGOUT) {
            response = process_logout_request(request);
        } else {
            response = create_error_response(std::format("Unknown request type: {}", request_type));
        }
        
        do_write(response + zerossg::MESSAGE_DELIMITER);
    } catch (const json::exception& e) {
        do_write(create_error_response(std::format("Invalid JSON: {}", e.what())) + zerossg::MESSAGE_DELIMITER);
    } catch (const std::exception& e) {
        do_write(create_error_response(std::format("Request processing error: {}", e.what())) + zerossg::MESSAGE_DELIMITER);
    }
}

zerossg::ResponseString Connection::process_login_request(const zerossg::RequestString& request) {
    json request_json = json::parse(request);
    zerossg::String username = request_json.value(zerossg::JSON_KEY_USERNAME, "");
    zerossg::String password = request_json.value(zerossg::JSON_KEY_PASSWORD, "");
    
    if (username.empty() || password.empty()) {
        return create_error_response(zerossg::ERROR_USERNAME_PASSWORD_REQUIRED);
    }
    
    // Check rate limiting
    auto rate_limit_result = m_server.m_security_manager->check_rate_limit(m_client_ip);
    if (!rate_limit_result.is_success() || !rate_limit_result.value()) {
        return create_error_response(zerossg::ERROR_RATE_LIMIT_EXCEEDED);
    }
    
    // Authenticate
    auto auth_result = m_server.m_auth_manager->authenticate(username, password);
    if (!auth_result.is_success()) {
        m_server.m_security_manager->record_failed_attempt(m_client_ip);
        return create_error_response(std::format("Authentication failed: {}", auth_result.error()));
    }
    
    m_server.m_security_manager->record_successful_login(m_client_ip);
    
    // Create user object
    auto user_result = m_server.m_auth_manager->get_user(username);
    if (!user_result.is_success() || !user_result.value().has_value()) {
        return create_error_response(zerossg::ERROR_USER_NOT_FOUND_AFTER_AUTH);
    }
    
    m_user = user_result.value().value();
    m_authenticated = true;
    
    zerossg::String token = auth_result.value();
    
    json response_data = {
        {zerossg::JSON_KEY_TOKEN, token},
        {zerossg::JSON_KEY_USER, {
            {zerossg::JSON_KEY_USERNAME, m_user.username},
            {zerossg::JSON_KEY_ROLE, role_to_string(m_user.role)}
        }}
    };
    
    return create_response(zerossg::JSON_VALUE_SUCCESS, zerossg::MESSAGE_LOGIN_SUCCESSFUL, response_data);
}

zerossg::ResponseString Connection::process_session_request(const zerossg::RequestString& request) {
    if (!m_authenticated) {
        return create_error_response(zerossg::ERROR_NOT_AUTHENTICATED);
    }
    
    json request_json = json::parse(request);
    zerossg::String target_service = request_json.value(zerossg::JSON_KEY_TARGET_SERVICE, "");
    
    if (target_service.empty()) {
        return create_error_response(zerossg::ERROR_TARGET_SERVICE_REQUIRED);
    }
    
    // Check authorization
    auto authz_result = m_server.m_authz_manager->can_access_service(m_user, target_service);
    if (!authz_result.is_success() || !authz_result.value()) {
        return create_error_response(std::format("Access denied to service: {}", target_service));
    }
    
    // Create session
    auto session_result = m_server.m_session_manager->create_session(m_user, m_client_ip, target_service);
    if (!session_result.is_success()) {
        return create_error_response(std::format("Session creation failed: {}", session_result.error()));
    }
    
    m_session_id = session_result.value();
    
    json response_data = {
        {zerossg::JSON_KEY_SESSION_ID, m_session_id},
        {zerossg::JSON_KEY_TARGET_SERVICE, target_service}
    };
    
    return create_response(zerossg::JSON_VALUE_SUCCESS, zerossg::MESSAGE_SESSION_CREATED, response_data);
}

zerossg::ResponseString Connection::process_proxy_request(const zerossg::RequestString& request) {
    if (!m_authenticated || m_session_id.empty()) {
        return create_error_response(zerossg::ERROR_NO_ACTIVE_SESSION);
    }
    
    // This is a simplified proxy implementation
    // In a real implementation, you would handle the actual data forwarding
    json response_data = {
        {zerossg::JSON_KEY_SESSION_ID, m_session_id},
        {zerossg::JSON_KEY_STATUS, zerossg::JSON_VALUE_PROXY_ACTIVE}
    };
    
    return create_response(zerossg::JSON_VALUE_SUCCESS, zerossg::MESSAGE_PROXY_REQUEST_PROCESSED, response_data);
}

zerossg::ResponseString Connection::process_logout_request(const zerossg::RequestString& request) {
    if (!m_authenticated) {
        return create_error_response(zerossg::ERROR_NOT_AUTHENTICATED);
    }
    
    // Terminate session if active
    if (!m_session_id.empty()) {
        m_server.m_session_manager->terminate_session(m_session_id);
        m_session_id.clear();
    }
    
    m_authenticated = false;
    
    return create_response(zerossg::JSON_VALUE_SUCCESS, zerossg::MESSAGE_LOGOUT_SUCCESSFUL);
}

void Connection::do_write(const zerossg::ResponseString& response) {
    boost::asio::async_write(
        m_socket, boost::asio::buffer(response),
        [self = shared_from_this()](const boost::system::error_code& error, size_t) {
            if (error) {
                self->m_server.m_logger->error(std::format("Write error: {}", error.message()));
            }
        }
    );
}

zerossg::ResponseString Connection::create_response(const zerossg::StatusString& status, const zerossg::MessageString& message, const json& data) {
    json response = {
        {zerossg::JSON_KEY_STATUS, status},
        {zerossg::JSON_KEY_MESSAGE, message},
        {zerossg::JSON_KEY_TIMESTAMP, zerossg::chrono::duration_cast<zerossg::chrono::seconds>(
            zerossg::chrono::system_clock::now().time_since_epoch()).count()}
    };
    
    if (!data.empty()) {
        response[zerossg::JSON_KEY_DATA] = data;
    }
    
    return response.dump();
}

zerossg::ResponseString Connection::create_error_response(const zerossg::ErrorString& error) {
    return create_response(zerossg::JSON_VALUE_ERROR, error);
}

void Connection::log_connection_event(const zerossg::EventTypeString& event_type, const zerossg::LogDetails& details) {
    m_server.m_logger->info(std::format("[{}] {}: {}", event_type, m_client_ip, details));
}

} // namespace zerossg
